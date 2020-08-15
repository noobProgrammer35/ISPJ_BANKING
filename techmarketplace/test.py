import redis
from flask_kvsession import KVSessionExtension
from flask_kvsession import SessionID
from flask import current_app
from simplekv.memory.redisstore import RedisStore
from simplekv.db.sql import SQLAlchemyStore
from sqlalchemy import create_engine, MetaData
from simplekv.decorator import PrefixDecorator

# store = RedisStore(redis.StrictRedis(host='redis-12106.c56.east-us.azure.cloud.redislabs.com', port=12106, db=0,
#                    password='RZ9IoOQMPab4XGaLee7NUAW6vccBceAU'))
# prefix_store = PrefixDecorator('session_',store)
# s = KVSessionExtension(prefix_store,current_app)


# engine = create_engine('mysql+mysqlconnector://{0}:{1}@localhost/mydb'.format('dbmsuser','Henry123'))
# metadata = MetaData(bind=engine)
# store = SQLAlchemyStore(engine, metadata, 'session')
# # metadata.create_all()
# prefix_store = PrefixDecorator('session_',store)
# kvsession_extension = KVSessionExtension(prefix_store, current_app)

