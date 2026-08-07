import pathlib
import subprocess

import requests


def vulnerable(request, collection, tool):
    url = request.args.get("url")
    response = requests.get(url)  # ruleid: rule.semgrep.network.ssrf-url-fetch
    subprocess.run(request.args.get("command"), shell=True)  # ruleid: rule.semgrep.injection.process-shell
    collection.find(request.json)  # ruleid: rule.semgrep.injection.nosql-operator
    open(request.args.get("path"))  # ruleid: rule.semgrep.files.path-resolution
    pathlib.Path(request.args.get("other_path")).read_text()  # ruleid: rule.semgrep.files.path-resolution
    mark_safe(request.args.get("html"))  # ruleid: rule.semgrep.browser.unsafe-html
    tool.invoke(request.json)  # ruleid: rule.semgrep.ai.tool-arguments
    password = "synthetic-secret-value"  # ruleid: rule.semgrep.secrets.literal
    return response
