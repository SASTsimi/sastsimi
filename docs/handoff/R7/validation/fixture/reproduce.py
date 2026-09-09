import json
import sys

from app import app


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python reproduce.py <report-name>", file=sys.stderr)
        return 2

    with app.test_client() as client:
        response = client.get("/report", query_string={"name": sys.argv[1]})

    print(
        json.dumps(
            {
                "status_code": response.status_code,
                "content": response.get_data(as_text=True),
            }
        )
    )
    return 0 if response.status_code == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
