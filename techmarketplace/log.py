import logging
import os
from techmarketplace import vault
from flask import request
import datetime
import psutil
from opencensus.ext.azure.log_exporter import AzureLogHandler
from opencensus.ext.azure import metrics_exporter
from opencensus.stats import aggregation,measure,stats,view
from opencensus.tags import tag_map

if not os.environ.get('IS_PROD',None):
    from techmarketplace import Configuration


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
if not os.environ.get('IS_PROD',None):
    logger.addHandler(AzureLogHandler(
        connection_string=Configuration.InstrumentKey
    ))
else:
    v = vault.Vault()
    logger.addHandler(AzureLogHandler(
        connection_string=os.environ.get('InstrumentKey')#v.get_secret('AzureLoggingConnectionString')
    ))
    v.close_all_connections()


# print(logger)
# # # # line = input('tet:')
# # # # logger.info(line)

# metric

# stat = stats.stats
# view_manager = stat.view_manager
# stats_recorder = stat.stats_recorder
# prompt_measure = measure.MeasureInt("prompts",
#                                            "number of prompts",
#                                            "prompts")
# prompt_view = view.View('Prompt view','number of prompts',[],prompt_measure,aggregation.CountAggregation())
#
#
# view_manager.register_view(prompt_view)
# mmap = stats_recorder.new_measurement_map()
# tmap =tag_map.TagMap()

#
# exporter = metrics_exporter.new_metrics_exporter(connection_string='InstrumentationKey=bec9fb90-0c7a-417a-809e-6c5417e4ba98')
# exporter.interval = 1
# view_manager.register_exporter(exporter)


# def prompt():
#     input("Press enter.")
#
#     # mmap.measure_int_put(prompt_measure, 1)
#     # mmap.record(tmap)
#     # metrics = list(mmap.measure_to_view_map.get_metrics(datetime.datetime.utcnow()))
#     # print(metrics[0].time_series[0].points[0])
#
# while True:
#     prompt()
#
