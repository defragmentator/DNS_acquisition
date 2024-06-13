#!/usr/bin/env python
import logging
import os
import threading
import time
from multiprocessing import Process
from queue import Queue
from file_appender import JSONConcatenater
import configparser
from confluent_kafka import Consumer, Producer

config = configparser.ConfigParser()
config.read('config.ini')
fields = eval(config['fields']['fields'])
fields = [ee[0] for ee in fields]
topic_in = config['db']['topic_in']
topic_out = config['db']['topic_out']
no_workers = int(config['kafka']['no_workers'])
no_threads = int(config['kafka']['no_threads'])


def delivery_report(err, msg):
    """ Called once for each message produced to indicate delivery result.
        Triggered by poll() or flush(). """
    if err is not None:
        print('Message delivery failed: {}'.format(err))
#    else:
#        print('Message delivered to {} [{}]'.format(msg.topic(), msg.partition()))


def _process_msg(q, c, p):
    msg = q.get(timeout=60)  # Set timeout to care for POSIX<3.0 and Windows.
    #logging.info(
    #    '#%sT%s - Received message: %s',
    #    os.getpid(), threading.get_ident(), msg.value().decode('utf-8')[:10]
    #)
    
    json = msg.value().decode('utf-8')
    json = JSONConcatenater(fields=fields).concatenate(json)
    #logging.info(
    #    '#%sT%s - Processed message: %s',
    #    os.getpid(), threading.get_ident(), json[:10]
    #)

    p.poll(0)
    p.produce(topic_out, json.encode('utf-8'), callback=delivery_report)
    p.flush()
    #logging.info(
    #    '#%sT%s - Producer passed message: %s',
    #    os.getpid(), threading.get_ident(), json[:10]
    #)

    
    
    q.task_done()
    c.commit(msg)


def _consume(config):
    logging.info(
        '#%s - Starting consumer group=%s, topic=%s',
        os.getpid(), config['kafka_kwargs']['group.id'], config['topic'],
    )
    c = Consumer(**config['kafka_kwargs'])
    c.subscribe([config['topic']])
    q = Queue(maxsize=config['num_threads'])

    p = Producer(**config['kafka_kwargs'])

    while True:
        #logging.info('#%s - Waiting for message...', os.getpid())
        try:
            msg = c.poll(1)
            if msg is None:
                continue
            if msg.error():
                logging.error(
                    '#%s - Consumer error: %s', os.getpid(), msg.error()
                )
                continue
            q.put(msg)
            # Use default daemon=False to stop threads gracefully in order to
            # release resources properly.
            t = threading.Thread(target=_process_msg, args=(q, c, p))
            t.start()
        except Exception:
            logging.exception('#%s - Worker terminated.', os.getpid())
            c.close()


def main(config):
    """
    Simple program that consumes messages from Kafka topic and prints to
    STDOUT.
    """
    workers = []
    while True:
        num_alive = len([w for w in workers if w.is_alive()])
        if config['num_workers'] == num_alive:
            time.sleep(1)
            continue
        for _ in range(config['num_workers']-num_alive):
            p = Process(target=_consume, daemon=True, args=(config,))
            p.start()
            workers.append(p)
            logging.info('Starting worker #%s', p.pid)


if __name__ == '__main__':
    logging.basicConfig(
        level=getattr(logging, os.getenv('LOGLEVEL', '').upper(), 'INFO'),
        format='[%(asctime)s] %(levelname)s:%(name)s:%(message)s',
    )
    main(config={
        # At most, this should be the total number of Kafka partitions on
        # the topic.
        'num_workers': no_workers,
        'num_threads': no_threads,
        'topic': topic_in,
        'kafka_kwargs': {
            'bootstrap.servers': ','.join([
                '127.0.0.1:9092',
            ]),
            'group.id': 'mygroup',
            #'auto.offset.reset': 'earliest',
            # Commit manually to care for abrupt shutdown.
            #'enable.auto.commit': False,
        },
    })
