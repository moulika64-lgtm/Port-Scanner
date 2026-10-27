
from flask import Flask, render_template, request
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP Alternate"
}


def is_allowed_target(host):
    try:
        addresses = socket.getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )

        if not addresses:
            return False

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not (ip.is_private or ip.is_loopback):
                return False

        return True

    except (socket.gaierror, ValueError, OSError):
        return False


def scan_port(host, port):
    try:
        with socket.create_connection(
            (host, port), timeout=0.5
        ):
            status = "Open"
    except OSError:
        status = "Closed / Filtered"

    return {
        "port": port,
        "service": COMMON_PORTS.get(port, "Unknown"),
        "status": status
    }


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    error = ""
    target = "127.0.0.1"
    start_port = 1
    end_port = 100

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        try:
            start_port = int(request.form.get("start_port", 1))
            end_port = int(request.form.get("end_port", 100))

            if not (1 <= start_port <= end_port <= 1024):
                raise ValueError(
                    "Ports must be between 1 and 1024."
                )

            if not is_allowed_target(target):
                raise ValueError(
                    "Use localhost or an authorized private IP."
                )

            with ThreadPoolExecutor(max_workers=50) as executor:
                tasks = [
                    executor.submit(scan_port, target, port)
                    for port in range(start_port, end_port + 1)
                ]

                for task in as_completed(tasks):
                    results.append(task.result())

            results.sort(key=lambda item: item["port"])

        except ValueError as exc:
            error = str(exc)

    open_count = sum(
        1 for result in results
        if result["status"] == "Open"
    )

    return render_template(
        "index.html",
        results=results,
        error=error,
        target=target,
        start_port=start_port,
        end_port=end_port,
        open_count=open_count
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
