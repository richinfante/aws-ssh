from datetime import datetime as dt
import uuid
import json
from hashlib import sha256
import logging
logger = logging.getLogger('aws-ssh')


ACK_TYPE = 3
INPUT_TYPE = 1
OUTPUT_TYPE = 0

START_PUBLICATION_MESSAGE = "start_publication"
OUTPUT_STREAM_DATA_MESSAGE = "output_stream_data"
INPUT_STREAM_DATA_MESSAGE = "input_stream_data"
ACKNOWLEDGE_MESSAGE = "acknowledge"

def convert_to_bytes(string):
  if isinstance(string, bytes):
    return string
  if isinstance(string, str):
    return string.encode()

  return string

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

def generate_digest(message):
  m = sha256()
  m.update(message)
  return m.hexdigest()

def botch_uuid(uuid_obj):
  return uuid_obj.bytes[8:16] + uuid_obj.bytes[0:8]

def unbotch_uuid(bytes_str):
  return uuid.UUID(bytes=bytes_str[8:16] + bytes_str[0:8])

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
  def __init__(self, socket, session_id, token_value, stream_url):
    self.socket = socket
    self.session_id = session_id
    self.token_value = token_value
    self.stream_url = stream_url
    self.sequence_number = 0

  def generate_token_message(self):
    return json.dumps({
      "MessageSchemaVersion": "1.0",
      "RequestId": str(uuid.uuid4()),
      "TokenValue": self.token_value
    })

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

  def send(self, msg):
    logger.debug("send: %s", msg)
    return self.socket.send(msg)

  def send_init(self, client_width, client_height):
    logger.debug('sending init with width=%s and height=%s', client_width, client_height)
    return self.send(self.generate_init_message(client_width, client_height))

  def send_ack(self, message):
    return self.send(self.generate_ack(
      message_type=message['message_type'],
      sequence_number=message['sequence_number'],
      message_id=str(message['message_id'])
    ))

  def send_text(self, text):
    self.sequence_number += 1
    return self.send(self.generate_input_message(text))



