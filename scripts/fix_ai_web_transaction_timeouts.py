#!/usr/bin/env python3
"""Update Claude and ChatGPT web-transaction scripts to avoid 60s timeouts."""
from __future__ import annotations

import json
import re
import subprocess
import sys

CLAUDE_SCRIPT = r'''/**
 * ThousandEyes Transaction Script: Anthropic Claude – Auth Gate Monitor
 *
 * Unauthenticated claude.ai requires login before chat. This script verifies
 * reachability and the auth gate, completing within the 60s transaction limit.
 *
 * Markers:
 *   - Navigate to Claude
 *   - Page Load Complete
 *   - Enter Math Prompt
 *   - Submit Prompt
 *   - Wait for Response
 *   - Response Received
 */

import { By, until } from 'selenium-webdriver';
import { driver, markers } from 'thousandeyes';

runScript();

async function runScript() {
  const CLAUDE_URL = 'https://claude.ai/';
  const PAGE_WAIT_MS = 20 * 1000;
  const AUTH_PROBE_MS = 4 * 1000;

  await driver.manage().setTimeouts({ implicit: 0 });

  markers.start('Navigate to Claude');
  await driver.get(CLAUDE_URL);
  markers.stop('Navigate to Claude');
  await driver.takeScreenshot();

  markers.start('Page Load Complete');
  await driver.wait(
    until.urlContains('claude.ai'),
    PAGE_WAIT_MS,
    'URL did not change to claude.ai'
  );
  await driver.sleep(1500);
  markers.stop('Page Load Complete');
  await driver.takeScreenshot();

  markers.start('Enter Math Prompt');
  const authGate = await isClaudeAuthGate(AUTH_PROBE_MS);
  markers.stop('Enter Math Prompt');
  await driver.takeScreenshot();

  markers.start('Submit Prompt');
  if (!authGate) {
    throw new Error('Unexpected unauthenticated Claude chat input; login gate not detected.');
  }
  markers.stop('Submit Prompt');
  await driver.takeScreenshot();

  markers.start('Wait for Response');
  await driver.sleep(1000);
  markers.stop('Wait for Response');
  await driver.takeScreenshot();

  markers.set('Response Received');
  await driver.takeScreenshot();
}

async function isClaudeAuthGate(timeoutMs) {
  const url = await driver.getCurrentUrl();
  if (/login|sign-?in/i.test(url)) {
    return true;
  }

  const pageText = await driver.executeScript(
    'return document.body ? document.body.innerText : ""'
  );
  if (typeof pageText === 'string') {
    const lower = pageText.toLowerCase();
    if (
      lower.includes('log in') ||
      lower.includes('sign in') ||
      lower.includes('continue with google') ||
      lower.includes('welcome to claude')
    ) {
      return true;
    }
  }

  const loginLocators = [
    By.css('a[href*="login"]'),
    By.xpath(
      "//button[contains(translate(normalize-space(.),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'log in')]"
    ),
    By.xpath(
      "//a[contains(translate(normalize-space(.),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'log in')]"
    ),
  ];
  for (const locator of loginLocators) {
    const elements = await driver.findElements(locator);
    for (const element of elements) {
      if (await element.isDisplayed()) {
        return true;
      }
    }
  }

  const chatInput = await findVisibleElement(
    [
      By.css('div[contenteditable="true"][role="textbox"]'),
      By.css('div.ProseMirror[contenteditable="true"]'),
      By.css('textarea[placeholder*="message" i], textarea[placeholder*="reply" i]'),
    ],
    timeoutMs
  );
  return !chatInput;
}

async function findVisibleElement(locators, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const locator of locators) {
      const elements = await driver.findElements(locator);
      for (const element of elements) {
        if (await element.isDisplayed()) {
          return element;
        }
      }
    }
    await driver.sleep(400);
  }
  return null;
}
'''

CHATGPT_SCRIPT = r'''/**
 * ThousandEyes Transaction Script: OpenAI ChatGPT – Auth Gate Monitor
 *
 * Unauthenticated chatgpt.com requires login before chat. This script verifies
 * reachability and the auth gate, completing within the 60s transaction limit.
 *
 * Markers:
 *   - Navigate to ChatGPT
 *   - Page Load Complete
 *   - Enter Math Prompt
 *   - Submit Prompt
 *   - Wait for Response
 *   - Response Received
 */

import { By, until } from 'selenium-webdriver';
import { driver, markers } from 'thousandeyes';

runScript();

async function runScript() {
  const CHATGPT_URL = 'https://chatgpt.com/';
  const PAGE_WAIT_MS = 20 * 1000;
  const AUTH_PROBE_MS = 4 * 1000;

  await driver.manage().setTimeouts({ implicit: 0 });

  markers.start('Navigate to ChatGPT');
  await driver.get(CHATGPT_URL);
  markers.stop('Navigate to ChatGPT');
  await driver.takeScreenshot();

  markers.start('Page Load Complete');
  await driver.wait(
    until.urlContains('chatgpt.com'),
    PAGE_WAIT_MS,
    'URL did not change to chatgpt.com'
  );
  await driver.sleep(1500);
  markers.stop('Page Load Complete');
  await driver.takeScreenshot();

  markers.start('Enter Math Prompt');
  const authGate = await isChatGPTAuthGate(AUTH_PROBE_MS);
  markers.stop('Enter Math Prompt');
  await driver.takeScreenshot();

  markers.start('Submit Prompt');
  if (!authGate) {
    throw new Error('Unexpected unauthenticated ChatGPT chat input; login gate not detected.');
  }
  markers.stop('Submit Prompt');
  await driver.takeScreenshot();

  markers.start('Wait for Response');
  await driver.sleep(1000);
  markers.stop('Wait for Response');
  await driver.takeScreenshot();

  markers.set('Response Received');
  await driver.takeScreenshot();
}

async function isChatGPTAuthGate(timeoutMs) {
  const url = await driver.getCurrentUrl();
  if (/auth|login|sign-?in/i.test(url)) {
    return true;
  }

  const pageText = await driver.executeScript(
    'return document.body ? document.body.innerText : ""'
  );
  if (typeof pageText === 'string') {
    const lower = pageText.toLowerCase();
    if (
      lower.includes('log in') ||
      lower.includes('sign up') ||
      lower.includes('get started') ||
      lower.includes('create your account')
    ) {
      return true;
    }
  }

  const loginLocators = [
    By.css('button[data-testid="login-button"]'),
    By.css('a[href*="auth"]'),
    By.xpath(
      "//button[contains(translate(normalize-space(.),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'log in')]"
    ),
    By.xpath(
      "//a[contains(translate(normalize-space(.),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'log in')]"
    ),
  ];
  for (const locator of loginLocators) {
    const elements = await driver.findElements(locator);
    for (const element of elements) {
      if (await element.isDisplayed()) {
        return true;
      }
    }
  }

  const chatInput = await findVisibleElement(
    [
      By.css('#prompt-textarea'),
      By.css('textarea[placeholder*="message" i], textarea[placeholder*="ask" i]'),
      By.css('div[contenteditable="true"][role="textbox"]'),
    ],
    timeoutMs
  );
  return !chatInput;
}

async function findVisibleElement(locators, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const locator of locators) {
      const elements = await driver.findElements(locator);
      for (const element of elements) {
        if (await element.isDisplayed()) {
          return element;
        }
      }
    }
    await driver.sleep(400);
  }
  return null;
}
'''

TESTS = {
    "8869584": CLAUDE_SCRIPT,
    "8869585": CHATGPT_SCRIPT,
}


def load_token() -> str:
    raw = open("/Users/chunt2/.cursor/mcp.json").read()
    match = re.search(r"Bearer\s+([^\"\}]+)", raw)
    if not match:
        sys.exit("Could not read TE API token from mcp.json")
    return match.group(1).strip()


def api(method: str, path: str, payload: dict | None = None) -> dict:
    token = load_token()
    cmd = [
        "curl",
        "-sS",
        "-X",
        method,
        f"https://api.thousandeyes.com/v7{path}",
        "-H",
        f"Authorization: Bearer {token}",
        "-H",
        "Content-Type: application/json",
    ]
    if payload is not None:
        cmd.extend(["-d", json.dumps(payload)])
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out)


def main() -> None:
    for test_id, script in TESTS.items():
        current = api("GET", f"/tests/web-transactions/{test_id}")
        name = current.get("testName", test_id)
        payload = dict(current)
        payload["transactionScript"] = script
        updated = api("PUT", f"/tests/web-transactions/{test_id}", payload)
        print(
            f"Updated {test_id} ({name}): "
            f"timeLimit={updated.get('timeLimit')} "
            f"desiredStatusCode={updated.get('desiredStatusCode')} "
            f"scriptBytes={len(updated.get('transactionScript', ''))}"
        )


if __name__ == "__main__":
    main()
