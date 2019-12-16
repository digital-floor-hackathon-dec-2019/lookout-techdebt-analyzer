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

                logger.debug("analyzing '%s' in %s",
                             change.head.path, change.head.language)
                try:
                    comments.append(
                        pb.Comment(
                            file=change.head.path,
                            line=0,
                            text="Hello from techdebt analyzer"))
                except Exception as e:
                    logger.exception("Error occurred while creating a comment: %s", e)
                    continue

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


def print_check_stats():
    num_checks = 0
    all_checks = collections.defaultdict(list)
    for lang in langs:
        checks = list_checks(lang)
        all_checks[lang].append(checks)
        num_checks += len(checks)
    logger.info("%d langs, %d checks supported", len(langs), num_checks)

    logger.debug("Langs: %s", langs)
    logger.debug("Checks: %s", checks)


def main():
    logger.info("starting gRPC Analyzer server at port %s", port_to_listen)
    print_check_stats()
    serve()


if __name__ == "__main__":
    main()
