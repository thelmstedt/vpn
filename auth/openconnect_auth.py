import aiohttp
import argparse
import asyncio
import json
import logging
import os
import playwright
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from playwright.async_api import async_playwright
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_CDP_URL = "http://localhost:9222"


async def _resolve_server_address(session: aiohttp.ClientSession, url: str) -> str:
    async with session.get(url) as response:
        await response.read()
    return str(response.url)


def _get_field(elem: ET.Element, name: str) -> str:
    node = elem.find(name)
    if node is None:
        raise ValueError(f"Node \"{name}\" isn't found")
    return node.text.strip()


def _build_session() -> aiohttp.ClientSession:
    return aiohttp.ClientSession(
        headers={
            "User-Agent": "AnyConnect Linux_64 4.7.00136",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "X-Transcend-Version": "1",
            "X-Aggregate-Auth": "1",
            "X-Support-HTTP-Auth": "true",
            "Content-Type": "application/x-www-form-urlencoded",
        }
    )


@dataclass
class _InitResult:
    response: ET.Element
    login_url: str
    login_url_final: str
    token_cookie_name: str


def _render_init_request(server: str) -> bytes:
    return f'''
<?xml version='1.0' encoding='UTF-8'?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
  <version who="vpn">4.7.00136</version>
  <device-id>linux-64</device-id>
  <group-select></group-select>
  <group-access>{server}</group-access>
  <capabilities>
    <auth-method>single-sign-on-v2</auth-method>
  </capabilities>
</config-auth>
'''.lstrip().encode('utf-8')


async def _do_init_request(session: aiohttp.ClientSession, server: str, debug: bool = False):
    request_data = _render_init_request(server)
    async with session.post(server, data=request_data) as response:
        response_raw = await response.text()
        response.raise_for_status()
    response = ET.fromstring(response_raw)
    if response.attrib.get('type') != 'auth-request':
        raise ValueError(f"Invalid init request:\n{response_raw}")

    return _InitResult(
        response=response,
        login_url=_get_field(response, 'auth/sso-v2-login'),
        login_url_final=_get_field(response, 'auth/sso-v2-login-final'),
        token_cookie_name=_get_field(response, 'auth/sso-v2-token-cookie-name')
    )


@dataclass
class _SSOResult:
    cookies: list[dict]
    sso_token: str


async def _do_sso_auth(
        init_result: _InitResult,
        screenshot_dir: Optional[Path] = None,
        debug: bool = False,
        cdp_url: str = _DEFAULT_CDP_URL
) -> _SSOResult:
    async with async_playwright() as p:
        try:
            browser = await p.chromium.connect_over_cdp(cdp_url)
        except Exception as e:
            raise ValueError(
                f"Cannot connect to chrome at {cdp_url}. "
                f"Is chrome running with --remote-debugging-port? Error: {e}"
            )

        # attach to existing context so we get the user's cookies/session,
        # don't create a fresh incognito-ish one
        context = browser.contexts[0] if browser.contexts else await browser.new_context()
        page = await context.new_page()

        try:
            await page.goto(init_result.login_url)
            logger.info("Loaded login page; waiting for redirect to final url")

            # since the user's already logged into msft in this profile, microsoft
            # will (usually) silently redirect through to login_url_final without
            # showing any form. if it DOES show a form, the user fills it in manually —
            # we just wait.
            final_url = init_result.login_url_final.strip().lower()

            while True:
                try:
                    await asyncio.sleep(2)
                    current_url = page.url.strip().lower()
                    if current_url == final_url:
                        logger.info("Reached login_url_final")
                        break

                    try:
                        content = await page.content()
                        if "You have successfully authenticated" in content:
                            logger.info("Received anyconnect success page")
                            break
                    except playwright._impl._errors.Error:
                        pass

                    # auto-click "stay signed in?" if it shows up
                    try:
                        stay_btn = await page.wait_for_selector('#idSIButton9', timeout=200)
                        await stay_btn.click()
                    except Exception:
                        pass

                except playwright._impl._errors.TimeoutError:
                    pass

            cookies = await context.cookies(urls=init_result.login_url_final)

        except Exception:
            if screenshot_dir is None:
                screenshot_dir = Path.cwd()
            screenshot_path = screenshot_dir.joinpath('sso_error.png')
            logger.exception(f"Saving screenshot of error to: {screenshot_path}")
            try:
                screenshot_content = await page.screenshot(type='png')
                screenshot_path.write_bytes(screenshot_content)
            except Exception:
                pass
            raise
        finally:
            # close the tab but NOT the browser (not ours to close)
            try:
                await page.close()
            except Exception:
                pass

        for cookie_record in cookies:
            if cookie_record['name'].lower() == init_result.token_cookie_name.lower():
                sso_token = cookie_record['value']
                break
        else:
            raise ValueError(
                f"Cannot find session token \"{init_result.token_cookie_name}\" in the cookie:\n"
                f"{json.dumps(cookies, indent=4)}"
            )

        return _SSOResult(cookies=cookies, sso_token=sso_token)


@dataclass
class _FinalResult:
    response: ET.Element
    session_token: str
    servercert: str


def _render_final_request(sso_token: str, init_response: ET.Element) -> bytes:
    opaque_elem = init_response.find('opaque')

    return f'''
<?xml version='1.0' encoding='UTF-8'?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
    <version who="vpn">4.7.00136</version>
    <device-id>linux-64</device-id>
    <session-token/>
    {ET.tostring(opaque_elem, encoding='unicode')}
    <auth>
      <sso-token>{sso_token}</sso-token>
    </auth>
</config-auth>
'''.lstrip().encode('utf-8')


async def _to_final_request(
        session: aiohttp.ClientSession, server: str, init_result: _InitResult,
        sso_result: _SSOResult, debug: bool = False
) -> _FinalResult:
    request_data = _render_final_request(sso_token=sso_result.sso_token, init_response=init_result.response)
    async with session.post(server, data=request_data) as response:
        response_raw = await response.text()
        response.raise_for_status()
    response = ET.fromstring(response_raw)
    if response.attrib.get('type') != 'complete':
        raise ValueError(f"Invalid final request:\n{response_raw}")
    auth_elem = response.find('auth')
    if auth_elem is None or auth_elem.attrib.get('id').lower() != 'success':
        raise ValueError(f"Final request has failed:\n{response_raw}")

    return _FinalResult(
        response=response,
        session_token=_get_field(response, 'session-token'),
        servercert=_get_field(response, 'config/vpn-base-config/server-cert-hash'),
    )


@dataclass
class AuthResult:
    session_token: str
    servercert: str
    server: str


async def openconnect_auth(
        server: str,
        screenshot_dir: Optional[Path] = None,
        debug: bool = False,
        cdp_url: str = _DEFAULT_CDP_URL
) -> AuthResult:
    async with _build_session() as session:
        server = await _resolve_server_address(session=session, url=server)

        logger.info("Start authentication")
        init_result = await _do_init_request(session=session, server=server, debug=debug)

        logger.info("Run SSO auth via chrome cdp")
        sso_result = await _do_sso_auth(
            init_result=init_result, screenshot_dir=screenshot_dir, debug=debug, cdp_url=cdp_url,
        )

        final_result = await _to_final_request(
            session=session, server=server, init_result=init_result, sso_result=sso_result, debug=debug
        )

        return AuthResult(
            session_token=final_result.session_token,
            servercert=final_result.servercert,
            server=server
        )


def main(args=None):
    logging.basicConfig(level=logging.INFO, format='{asctime} {levelname} [{name}] {message}', style='{')
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', help='server', required=True)
    parser.add_argument('--output-config', help='Output config with auth results', required=True)
    parser.add_argument('--debug', help="Debug mode", action='store_true')
    parser.add_argument(
        '--cdp-url', help='chrome devtools protocol url',
        default=_DEFAULT_CDP_URL
    )
    parsed_args = parser.parse_args(args)

    output_result = Path(parsed_args.output_config)
    if not output_result.parent.is_dir():
        raise ValueError(f"Output config directory \"{output_result.parent}\" doesn't exist")

    result = asyncio.run(
        openconnect_auth(
            server=parsed_args.server,
            debug=parsed_args.debug,
            cdp_url=parsed_args.cdp_url,
        )
    )

    logger.info("Save results")
    with output_result.open('w', encoding='utf-8') as f:
        f.write(f"OPENCONNECT_AUTH_COOKIE='{result.session_token}'\n")
        f.write(f"OPENCONNECT_AUTH_SERVERCERT='{result.servercert}'\n")
        f.write(f"OPENCONNECT_AUTH_SERVER='{result.server}'\n")

    logger.info("Complete")


if __name__ == '__main__':
    main()
