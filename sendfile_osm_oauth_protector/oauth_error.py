class OAuthError(Exception):
    def __init__(self, message, error_response):
        """
        Args:
            message (str): message of the exception which was raised
            error_response (str): HTTP error code and description to be sent to the client
        """
        super(Exception, self).__init__(message)
        self.error_message = error_response
