import sys

import provablyfine.client
import provablyfine.tui.app


def main() -> None:
    config_file = sys.argv[1]
    cfg = provablyfine.client.Config.load(config_file)
    auth = provablyfine.client.Factory(cfg).async_session()
    provablyfine.tui.app.TuiApp(auth).run()


if __name__ == "__main__":
    main()
