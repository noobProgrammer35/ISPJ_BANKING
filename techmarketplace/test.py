import redis
import os
from flask_kvsession import KVSessionExtension
from flask_kvsession import SessionID
from flask import current_app
from simplekv.memory.redisstore import RedisStore
from simplekv.db.sql import SQLAlchemyStore
from sqlalchemy import create_engine, MetaData
from simplekv.decorator import PrefixDecorator

if os.environ.get('IS_PROD',None):
    store = RedisStore(redis.StrictRedis(host=os.environ.get('redis_host',None), port=os.environ.get('redis_port',None), db=os.environ.get('db',None),
                       password=os.environ.get('redis_password')))
    prefix_store = PrefixDecorator('session_',store)
    s = KVSessionExtension(prefix_store,current_app)
else:
    if os.environ.get('IS_PROD'):
        engine = create_engine(os.environ.get('CLEARDB_DATABASE_URL'))
    else:
        from techmarketplace import  Configuration
        engine = create_engine('mysql+mysqlconnector://{0}:{1}@localhost/projectdb'.format(Configuration.dbuser,Configuration.dbpw))
    metadata = MetaData(bind=engine)
    store = SQLAlchemyStore(engine, metadata, 'session')
    # metadata.create_all()
    prefix_store = PrefixDecorator('session_',store)
    kvsession_extension = KVSessionExtension(prefix_store, current_app)

