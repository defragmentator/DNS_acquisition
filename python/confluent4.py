#!/usr/bin/python3
from confluent_kafka import Consumer
from confluent_kafka import Producer
from file_appender import JSONConcatenater
import configparser

import time


config = configparser.ConfigParser()
config.read('config.ini')
fields = eval(config['fields']['fields'])
fields = [ee[0] for ee in fields]
topic_in = config['db']['topic_in']
topic_out = config['db']['topic_out']


p = Producer({'bootstrap.servers': '127.0.0.1:9092'})

c = Consumer({
    'bootstrap.servers': '127.0.0.1:9092',
    'group.id': 'grupa1_in',
# przetwarza nawet to co przetworzone juz
#    'auto.offset.reset': 'earliest'
})

def delivery_report(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        print('Message delivery failed: {}'.format(err))
#    else:
#        print('Message delivered to {} [{}]'.format(msg.topic(), msg.partition()))


c.subscribe([topic_in])
i=0
start = time.time()
while True:
    i+=1
    msg = c.poll(1.0)

    if msg is None:
        continue
    if msg.error():
        print("Consumer error: {}".format(msg.error()))
        continue

    #print('Received message: {}'.format(msg.value().decode('utf-8')))
    json = msg.value().decode('utf-8')
    #print(json)

    
    json = JSONConcatenater(fields=fields).concatenate(json)
    p.poll(0)
    p.produce(topic_out, json.encode('utf-8'), callback=delivery_report)
    p.flush()
    if(i==100):
        done = time.time()
        elapsed = done - start
        print(elapsed)
        i=0
        start = time.time()
c.close()
