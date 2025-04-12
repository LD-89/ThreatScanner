import cmd

from threat_scanner import ThreatScanner


class ThreatScannerCLI(cmd.Cmd):
    prompt = "ThreatScan>> "
    intro = "Welcome to ThreatScanner! Type help to learn more."

    def __init__(self):
        super().__init__()
        self.app = ThreatScanner()

    def do_get_sources(self, limit: str):
        """
        Get sources from feeds.
        Pass the number of websites you want to fetch.
        Default limit set to 100.
        """
        if not limit:
            limit = 100
        self.app.get_sources(int(limit))

    def do_print_sources(self, line):
        """Print sources to the terminal."""
        self.app.print_sources()

    def do_save_sources(self, data_format: str):
        """
        Save sources to a csv file.
        Specify type:
        - csv, json, txt or md for file storage
        - csv, json for S3 storage
        Default type is csv.
        """
        if not data_format:
            data_format = "csv"
        self.app.save_sources(data_format)

    def do_scan(self, line):
        """
        Scan all websites on VirusTotal GoogleSafeBrowsing and check if they are alive.
        """
        self.app.scan_websites()

    def do_print_reports(self, line):
        """Print scanning reports to the terminal."""
        self.app.print_reports()

    def do_compare(self, line):
        """Run comparison on results."""
        self.app.compare_results()

    def do_print_results(self, line):
        """Print final report to the terminal."""
        self.app.print_results()

    def do_save_results(self, data_format: str):
        """
        Save final report to a file.
        Specify type:
        - csv, json, txt or md for file storage
        - csv, json for S3 storage
        Default type is json.
        """
        if not data_format:
            data_format = "json"
        self.app.save_results(data_format)

    def do_quit(self, line):
        """Quit the CLI."""
        return True

    def postcmd(self, stop, line):
        print()
        return stop

if __name__ == '__main__':
    ThreatScannerCLI().cmdloop()
