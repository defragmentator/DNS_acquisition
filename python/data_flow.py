import configparser
import os
from clickhouse_driver import Client
from file_appender import SQLFieldsAppender
import re

config = configparser.ConfigParser()
config.read('config.ini')


DATABASE_NAME = config['db']['db_name']
TOPIC_IN = config['db']['topic_in']
TOPIC_OUT = config['db']['topic_out']
NO_PARTITIONS = config['kafka']['no_partitions']


USER = ''
PASSWORD = ''


def setup_topics():
    os.system("/usr/local/kafka/bin/kafka-topics.sh --zookeeper localhost:2181 "
              "--delete --topic {TOPIC_IN}".format(TOPIC_IN=TOPIC_IN))
    os.system("/usr/local/kafka/bin/kafka-topics.sh --zookeeper localhost:2181 "
              "--delete --topic {TOPIC_OUT}".format(TOPIC_OUT=TOPIC_OUT))
    os.system("/usr/local/kafka/bin/kafka-topics.sh --create --zookeeper localhost:2181 --topic {TOPIC_IN} "
              "--replication-factor 1 --partitions {NO_PARTITIONS}".format(TOPIC_IN=TOPIC_IN, NO_PARTITIONS=NO_PARTITIONS))
    os.system("/usr/local/kafka/bin/kafka-topics.sh --create --zookeeper localhost:2181 --topic {TOPIC_OUT} "
              "--replication-factor 1 --partitions {NO_PARTITIONS}".format(TOPIC_OUT=TOPIC_OUT, NO_PARTITIONS=NO_PARTITIONS))



def open_creds():
    f = open('creds', 'r')
    lines = f.read().split('\n')
    global USER
    USER = lines[0]
    global PASSWORD
    PASSWORD = lines[1]
    f.close()


def open_plain(path, database_name, topic=None):
    f = open(path, 'r')
    content = f.read()
    content = content.replace('test3', DATABASE_NAME)

    if topic is not None:
        found = re.search("Kafka\('localhost:9092', (.*?),", content)
        content = content.replace(content[found.regs[0][0]: found.regs[0][1]], "Kafka('localhost:9092', '" + topic + "',")
    f.close()

    return content



setup_topics()

open_creds()

c = Client(host='localhost', port=9000, database=DATABASE_NAME, user=USER, password=PASSWORD,
           settings={'use_numpy': True})




fields = eval(config['fields']['fields']) #[('Response_Answers.dns_a', 'Nullable(IPv4)'), ('Response_Additional_records.dns_a', 'Nullable(IPv4)')]

types_asn_dest_fields = eval(config['fields']['destination_fields'])

c.execute('drop table if exists {DB_NAME}.no_types'.format(DB_NAME=DATABASE_NAME))
c.execute(open_plain('no_types.sql', DATABASE_NAME).format(DB_NAME=DATABASE_NAME))

c.execute('drop table if exists {DB_NAME}.types'.format(DB_NAME=DATABASE_NAME))
c.execute(open_plain('types.sql', DATABASE_NAME))

c.execute('drop table if exists {DB_NAME}.convert_types_at_start'.format(DB_NAME=DATABASE_NAME))
c.execute(open_plain('convert_types.sql', DATABASE_NAME))

c.execute('drop table if exists {DB_NAME}.kafka_types'.format(DB_NAME=DATABASE_NAME))
c.execute(open_plain('kafka_types.sql', DATABASE_NAME, TOPIC_IN))

c.execute('drop table if exists {DB_NAME}.pass_to_kafka'.format(DB_NAME=DATABASE_NAME))
c.execute('create materialized view {DB_NAME}.pass_to_kafka to kafka_types as select * from types'.format(DB_NAME=DATABASE_NAME))

c.execute('drop table if exists {DB_NAME}.kafka_types_z_asn'.format(DB_NAME=DATABASE_NAME))
SQLFieldsAppender(file='kafka_types_z_asn.sql', fields = fields, destination_fields=types_asn_dest_fields).append2()
sql = open_plain('kafka_types_z_asn.sql_append', DATABASE_NAME, TOPIC_OUT)
c.execute(sql)

c.execute('drop table if exists {DB_NAME}.types_z_asn'.format(DB_NAME=DATABASE_NAME))
fields = [('Response_Answers.dns_a', ''), ('Response_Additional_records.dns_a', '')]
SQLFieldsAppender(file='types_z_asn.sql', fields=fields, destination_fields=types_asn_dest_fields).append2()
sql = open_plain('types_z_asn.sql_append', DATABASE_NAME)
c.execute(sql)

c.execute('drop table if exists {DB_NAME}.pass_from_kafka_to_db'.format(DB_NAME=DATABASE_NAME))
c.execute('create materialized view {DB_NAME}.pass_from_kafka_to_db to types_z_asn as select * from {DB_NAME}.kafka_types_z_asn'.format(DB_NAME=DATABASE_NAME))


