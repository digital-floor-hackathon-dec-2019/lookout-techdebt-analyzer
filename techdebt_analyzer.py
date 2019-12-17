#!/usr/bin/env python3

# Analyzer that wraps https://github.com/bblfsh/sonar-checks

from concurrent.futures import ThreadPoolExecutor

import os
import time
import grpc
import collections
import logging

from lookout.sdk import pb
from lookout.sdk.service_data import DataStub
from lookout.sdk.grpc import to_grpc_address, create_channel, create_server, \
    LogUnaryServerInterceptor, LogStreamServerInterceptor, \
    LogUnaryClientInterceptor, LogStreamClientInterceptor
from bblfsh_sonar_checks import run_checks, list_checks
from bblfsh_sonar_checks.utils import list_langs
from bblfsh import filter as filter_uast

version = "alpha"
host_to_bind = os.getenv('TECHDEBT_HOST', "0.0.0.0")
port_to_listen = os.getenv('TECHDEBT_PORT', 9928)
data_srv_addr = to_grpc_address(
    os.getenv('TECHDEBT_DATA_SERVICE_URL', "ipv4://localhost:10301"))
log_level = os.getenv('TECHDEBT_LOG_LEVEL', "info").upper()

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
logger.addHandler(handler)
logger.setLevel(log_level)

langs = list_langs()


def log_fn(log_fields, msg):
    logger.debug("{msg} [{log_fields}]".format(
        msg=msg, log_fields=log_fields.fields))


class Analyzer(pb.AnalyzerServicer):
    def notify_review_event(self, request, context):
        logger.debug("got review request %s", request)

        comments = []

        # client connection to DataServe
        with create_channel(data_srv_addr, interceptors=[
                LogUnaryClientInterceptor(log_fn),
                LogStreamClientInterceptor(log_fn),
        ]) as channel:
            stub = DataStub(channel)
            changes = stub.get_changes(
                context,
                pb.ChangesRequest(
                    head=request.commit_revision.head,
                    base=request.commit_revision.base,
                    want_contents=False,
                    want_uast=True,
                    exclude_vendored=True,
                    include_languages=langs))

            for change in changes:
                if not change.HasField("head"):
                    continue

                if change.head.path.endswith("/Environment.java"):
                    try:
                        comments.append(
                            pb.Comment(
                                file=change.head.path,
                                line=0,
                                text="This source file is a frequently changed file with significant technical debt.\n\nLeave the campground cleaner than you found it! Improvement estimate: starting at 5 mins.",
                                confidence=94))
                        logger.debug("commented on non-hotspot file: %s", change.head.path)
                    except Exception as e:
                        logger.exception("Error occurred while creating a comment: %s", e)
                        continue
                else:
                  logger.debug("skipping non-hotspot file: %s", change.head.path)

        logger.info("%d comments produced", len(comments))

        return pb.EventResponse(analyzer_version=version, comments=comments)

    def notify_push_event(self, request, context):
        return pb.EventResponse(analyzer_version=version)


def serve():
    server = create_server(10, interceptors=[
        LogUnaryServerInterceptor(log_fn),
        LogStreamServerInterceptor(log_fn),
    ])
    pb.add_analyzer_to_server(Analyzer(), server)
    server.add_insecure_port("{}:{}".format(host_to_bind, port_to_listen))
    server.start()

    one_day_sec = 60*60*24
    try:
        while True:
            time.sleep(one_day_sec)
    except KeyboardInterrupt:
        server.stop(0)


def main():
    logger.info("starting gRPC Analyzer server at port %s", port_to_listen)
    serve()


if __name__ == "__main__":
    main()
