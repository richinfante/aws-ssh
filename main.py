import boto3
import websockets
import asyncio
import shutil
import ssm_packets
import time
import logging
import logging
import sys
import tty
import termios

fd = sys.stdin.fileno()
old_settings = termios.tcgetattr(fd)

logger = logging.getLogger('aws-ssh')
logger.setLevel(logging.INFO)

AUTOTYPE_PROFILE = "cd && bash -l && exit"

# These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

def formatter_message(message, use_color = True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

COLORS = {
    'WARNING': YELLOW,
    'INFO': GREEN,
    'DEBUG': BLUE,
    'CRITICAL': YELLOW,
    'ERROR': RED
}

class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color = True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname])
            record.color = levelname_color
            record.end_color = RESET_SEQ
        return logging.Formatter.format(self, record) + '\r'


handler = logging.StreamHandler(sys.stdout)
formatter = ColoredFormatter("%(color)s%(asctime)s %(name)s- %(levelname)s%(end_color)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

import signal
import sys


tgt_instance_id = None
tgt_hostname = None

for item in sys.argv:
  if item == 'main.py':
    continue
  if item.startswith('i-'):
    tgt_instance_id = item
    break
  else:
    tgt_hostname = item
    break


if not tgt_instance_id:
  ec2_client = boto3.client('ec2')

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

if tgt_hostname:
  logger.info('connecting to %s (%s)...', tgt_instance_id, tgt_hostname)
else:
  logger.info('connecting to %s...' % tgt_instance_id)

client = boto3.client('ssm')
session = client.start_session(
  Target=tgt_instance_id
)

logger.info('got session id %s', session['SessionId'])

async def hello(loop):
    uri = session['StreamUrl']
    logger.debug("wss: connecting to %s" % uri)
    async with websockets.connect(
        uri=uri,
        ping_interval=None
    ) as websocket:
      ssm = ssm_packets.SSMProtocolHandler(websocket, session['SessionId'], session['TokenValue'], session['StreamUrl'])

      async def consumer_handler(websocket, ssm):
        logger.debug("comsumer started.")
        async for message in websocket:
          msg = ssm_packets.deserialize_message(message)

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

        if AUTOTYPE_PROFILE:
          await ssm.send_text(AUTOTYPE_PROFILE + '\n')

        # time.sleep(5)
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
            # data = sys.stdin.read(5)
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
  client.terminate_session(
      SessionId=session['SessionId']
  )

def signal_handler(sig, frame):
  cleanup()
  sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
loop = asyncio.get_event_loop()
loop.run_until_complete(asyncio.gather(hello(loop)))

cleanup()