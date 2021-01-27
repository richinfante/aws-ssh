import argparse
import asyncio
import boto3
from datetime import datetime as dt
import hashlib
import json
import logging
import shutil
import signal
import sys
import tty
import termios
import uuid
import websockets

# Load terminal attrs / stdin fd
fd = sys.stdin.fileno()
old_settings = termios.tcgetattr(fd)

# Global loggers + session state
logger = logging.getLogger('aws-ssh')
logger.setLevel(logging.INFO)
ec2_client = boto3.client('ec2')
ssm_client = boto3.client('ssm')
session = None

# An auto-typable profile, auto-sent.
# this is needed since `sh` doesn't handle *anything* very nicely.
AUTOTYPE_PROFILE = "cd && bash -l && exit"

# SSM message Types
ACK_TYPE = 3
INPUT_TYPE = 1
OUTPUT_TYPE = 0

# Message Names
START_PUBLICATION_MESSAGE = "start_publication"
OUTPUT_STREAM_DATA_MESSAGE = "output_stream_data"
INPUT_STREAM_DATA_MESSAGE = "input_stream_data"
ACKNOWLEDGE_MESSAGE = "acknowledge"

# These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

# Convert a string to bytes
def convert_to_bytes(string):
  if isinstance(string, bytes):
    return string
  if isinstance(string, str):
    return string.encode()

  return string

# Build a message for the agent
def build_agent_message(payload, message_type, sequence_number, payload_type, flags):
  msg_bytes = convert_to_bytes(payload)

  return {
    'header_length': 116,
    'message_type': message_type,
    'schema_version': 1,
    'created_date': dt.utcnow().replace(microsecond=0),
    'sequence_number': sequence_number,
    'flags': flags,
    'message_id': uuid.uuid4(),
    'payload_type': payload_type,
    'payload_digest': generate_digest(msg_bytes),
    'payload_length': len(msg_bytes),
    'payload': msg_bytes
  }

# Generate SHA-256 digest of the message
def generate_digest(message):
  m = hashlib.sha256()
  m.update(message)
  return m.hexdigest()

# UUIDS are formatted backwards with the first 8 bytes swapped with the last.
# This performs the swap.
def botch_uuid(uuid_obj):
  return uuid_obj.bytes[8:16] + uuid_obj.bytes[0:8]

# UUIDS are formatted backwards with the first 8 bytes swapped with the last.
# This reverses the swap.
def unbotch_uuid(bytes_str):
  return uuid.UUID(bytes=bytes_str[8:16] + bytes_str[0:8])

# Serialize a message dict for writing to the socket
def serialize_message(msg):
  logger.debug("deserializing: %s", msg)
  out = b''
  out += msg['header_length'].to_bytes(4, byteorder='big')
  # maxlen: 32 inside slice, left justified with nulls
  out += msg['message_type'][0:32].ljust(32, ' ').encode()
  out += msg['schema_version'].to_bytes(4, byteorder='big')
  out += int(msg['created_date'].timestamp() * 1000).to_bytes(8, byteorder='big')
  out += msg['sequence_number'].to_bytes(8, byteorder='big')
  out += msg['flags'].to_bytes(8, byteorder='big')
  out += botch_uuid(msg['message_id'])
  out += bytes.fromhex(msg['payload_digest'])
  out += msg['payload_type'].to_bytes(4, byteorder='big')
  out += msg['payload_length'].to_bytes(4, byteorder='big')
  assert(len(out) == 120)
  out += msg['payload']
  return out

# Deserialize a message from the socket
def deserialize_message(input):
  logger.debug('deserilize: %s' % input)

  ts = int.from_bytes(input[40:48], byteorder='big') / 1000
  digest = input[80:112]

  try:
    digest = digest.hex()
  except:
    logger.debug("failed to decode: %s" % digest)

  res = {
    'header_length': int.from_bytes(input[0:4], byteorder='big'),
    'message_type': input[4:36].decode().replace('\x00', '').replace(' ', ''),
    'schema_version': int.from_bytes(input[36:40], byteorder='big'),
    'created_date': dt.utcfromtimestamp(ts),
    'sequence_number': int.from_bytes(input[48:56], byteorder='big'),
    'flags': int.from_bytes(input[56:64], byteorder='big'),
    'message_id': unbotch_uuid(input[64:80]),
    'payload_digest': digest,
    'payload_type': int.from_bytes(input[112:116], byteorder='big'),
    'payload_length': int.from_bytes(input[116:120], byteorder='big'),
    'payload': input[120:]
  }

  logger.debug("result: %s" % res)
  return res

class SSMProtocolHandler:
  # Initialize with state
  def __init__(self, socket, session_id, token_value, stream_url):
    self.socket = socket
    self.session_id = session_id
    self.token_value = token_value
    self.stream_url = stream_url
    self.sequence_number = 0

  # Generate initial token auth message
  def generate_token_message(self):
    return json.dumps({
      "MessageSchemaVersion": "1.0",
      "RequestId": str(uuid.uuid4()),
      "TokenValue": self.token_value
    })

  # Generate a session init message
  def generate_init_message(self, client_width, client_height):
    return serialize_message(build_agent_message(
      payload=json.dumps({
        'cols': client_width,
        'rows': client_height
      }),
      message_type="input_stream_data",
      sequence_number=self.sequence_number,
      payload_type=ACK_TYPE,
      flags=1
    ))

  def generate_input_message(self, text):
    return serialize_message(build_agent_message(
      payload=text,
      message_type="input_stream_data",
      sequence_number=self.sequence_number,
      payload_type=INPUT_TYPE,
      flags=0 if self.sequence_number == 1 else 1
    ))

  # Generate an ACK message
  def generate_ack(self, message_type, sequence_number, message_id):
    return serialize_message(build_agent_message(
      payload=json.dumps({
        "AcknowledgedMessageType": message_type,
        "AcknowledgedMessageId": message_id,
        "AcknowledgedMessageSequenceNumber": sequence_number,
        "IsSequentialMessage": True
      }),
      message_type="acknowledge",
      sequence_number=sequence_number,
      payload_type=ACK_TYPE,
      flags=0
    ))

  # Send a message
  def send(self, msg):
    logger.debug("send: %s", msg)
    return self.socket.send(msg)

  # Setup session with width / height
  def send_init(self, client_width, client_height):
    logger.debug('sending init with width=%s and height=%s', client_width, client_height)
    return self.send(self.generate_init_message(client_width, client_height))

  # Send ACK message over ws
  def send_ack(self, message):
    return self.send(self.generate_ack(
      message_type=message['message_type'],
      sequence_number=message['sequence_number'],
      message_id=str(message['message_id'])
    ))

  # Send text over websockets
  def send_text(self, text):
    self.sequence_number += 1
    return self.send(self.generate_input_message(text))

# Log formatting message
def formatter_message(message, use_color=True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message


# Find log colors
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

# Assign color levels
COLORS = {
    'WARNING': YELLOW,
    'INFO': GREEN,
    'DEBUG': BLUE,
    'CRITICAL': YELLOW,
    'ERROR': RED
}

# Colored formatter for terminal
class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color=True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname])
            record.color = levelname_color
            record.end_color = RESET_SEQ
        return logging.Formatter.format(self, record) + '\r'

# Main session handler - run in event loop
async def main_session_handler(loop):
  global session

  uri = session['StreamUrl']
  logger.debug("wss: connecting to %s" % uri)
  async with websockets.connect(
      uri=uri,
      ping_interval=None
  ) as websocket:
    ssm = SSMProtocolHandler(websocket, session['SessionId'], session['TokenValue'], session['StreamUrl'])

    async def consumer_handler(websocket, ssm):
      logger.debug("comsumer started.")
      async for message in websocket:
        msg = deserialize_message(message)

        logger.debug("recieved: %s" % msg)
        if msg['message_type'] in ['output_stream_data']:
          await ssm.send_ack(msg)

        if msg['payload_type'] == 1:
          sys.stdout.write(msg['payload'].decode().replace('\n', '\r\n'))
          sys.stdout.flush()
          logger.debug("got text payload: %s" % msg['payload'])
        elif msg['payload_type'] == 17:
          logger.debug("need to resend init")
          terminal_size = shutil.get_terminal_size()
          term_width = terminal_size.columns
          term_height = terminal_size.lines

          await ssm.send_init(term_width, term_height)

    async def producer_handler(websocket, ssm):
      logger.debug("producer started.")
      # time.sleep(10)
      terminal_size = shutil.get_terminal_size()
      term_width = terminal_size.columns
      term_height = terminal_size.lines

      await ssm.send(ssm.generate_token_message())
      await ssm.send_init(term_width, term_height)

      await asyncio.sleep(1)

      if AUTOTYPE_PROFILE:
        await ssm.send_text(AUTOTYPE_PROFILE + '\n')

      while True:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        tty.setraw(sys.stdin.fileno())
        try:
          data = await loop.run_in_executor(None, sys.stdin.buffer.read, 1)
          termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
          logger.debug('send text: %s', data)
          if data == b'':
            logger.info('detected logout, cleaning up...')
            await ssm.send_text('\x04')
            break

          await ssm.send_text(data)
        except Exception:
          await ssm.send_text('\x04')
          break

    consumer_task = asyncio.ensure_future(
        consumer_handler(websocket, ssm))
    producer_task = asyncio.ensure_future(
        producer_handler(websocket, ssm))
    done, pending = await asyncio.wait(
        [producer_task, consumer_task],
        return_when=asyncio.FIRST_EXCEPTION,
    )

    for task in pending:
        task.cancel()


def cleanup():
  termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
  logger.info('terminating session... (you may need to press enter)')
  ssm_client.terminate_session(
    SessionId=session['SessionId']
  )

def signal_handler(sig, frame):
  cleanup()
  sys.exit(0)

def main():
  global session

  # Setup logging
  handler = logging.StreamHandler(sys.stdout)
  formatter = ColoredFormatter("%(color)s%(asctime)s %(name)s- %(levelname)s%(end_color)s - %(message)s")
  handler.setFormatter(formatter)
  logger.addHandler(handler)

  # Parse args
  parser = argparse.ArgumentParser()
  parser.add_argument('hostname', help='hostname or instance ID')
  args = parser.parse_args()

  # Store hostname targets
  target = args.hostname
  tgt_instance_id = None
  tgt_hostname = None

  # Parse args
  if target.startswith('i-'):
    tgt_instance_id = target
  else:
    tgt_hostname = target

  # If no instance ID, look up via the tag
  if not tgt_instance_id:
    inst = ec2_client.describe_instances(
      Filters=[
        {
          'Name': 'tag:Name',
          'Values': [
            tgt_hostname
          ]
        }
      ]
    )

    if len(inst['Reservations'][0]['Instances']) == 0:
      raise Exception('instance not found')

    elif len(inst['Reservations'][0]['Instances']) > 1:
      raise Exception('multiple instances found, tag is ambiguous!')
    else:
      tgt_instance_id = inst['Reservations'][0]['Instances'][0]['InstanceId']

  # Print hostname
  if tgt_hostname:
    logger.info('connecting to %s (%s)...', tgt_instance_id, tgt_hostname)
  else:
    logger.info('connecting to %s...' % tgt_instance_id)

  session = ssm_client.start_session(
    Target=tgt_instance_id
  )

  logger.info('got session id %s', session['SessionId'])

  signal.signal(signal.SIGINT, signal_handler)
  loop = asyncio.get_event_loop()
  loop.run_until_complete(asyncio.gather(main_session_handler(loop)))

  cleanup()


# Run main()
if __name__ == "__main__":
  main()
