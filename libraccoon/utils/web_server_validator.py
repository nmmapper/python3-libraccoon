from urllib3.exceptions import HTTPError
from requests.exceptions import ConnectionError, TooManyRedirects
from libraccoon.utils.request_handler import RequestHandler
from libraccoon.utils.singleton import Singleton
from libraccoon.utils.exceptions import WebServerValidatorException, RequestHandlerException

class WebServerValidator(metaclass=Singleton):

    def __init__(self):
        self.request_handler = RequestHandler()

    def validate_target_webserver(self, host):
        try:
            self.request_handler.send(
                "GET",
                timeout=20,
                url="https://{}".format(
                    #host.protocol,
                    host.target,
                #    host.port
                )
            )
            return True
        except RequestHandlerException as e:
            print("ERROR ", e)
            raise WebServerValidatorException
