require("net/http");

AS2 = function() {
  function Client(partner_name) {
    this._partner = Config.partners[partner_name];
    if (!this._partner) throw "Partner " + partner_name + " is not registered";
    this._info = Config.server_info
  };

  Client.Result = new Struct("success", "response", "mic_matched", "mid_matched", "body", "disp_code");

  Client.prototype.send_file = function(file_name) {
    var self = this;
    var http = new Net.HTTP(this._partner.url.host, this._partner.url.port);
    http.use_ssl = this._partner.url.scheme == "https";

    // http.set_debug_output $stderr
    http.start(function() {
      var req = new Net.HTTP.Post(self._partner.url.path);
      req["AS2-Version"] = "1.2";
      req["AS2-From"] = self._info.name;
      req["AS2-To"] = self._partner.name;
      req["Subject"] = "AS2 EDI Transaction";
      req["Content-Type"] = "application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m";
      req["Disposition-Notification-To"] = self._info.url.to_s;
      req["Disposition-Notification-Options"] = "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha1";
      req["Content-Disposition"] = "attachment; filename=\"smime.p7m\"";
      req["Recipient-Address"] = self._info.url.to_s;
      req["Content-Transfer-Encoding"] = "base64";
      req["Message-ID"] = "<" + self._info.name + "-" + Time.now.strftime("%Y%m%d%H%M%S") + "@" + self._info.url.host + ">";
      var body = new StringIO;
      body.puts("Content-Type: application/EDI-Consent");
      body.puts("Content-Transfer-Encoding: base64");
      body.puts("Content-Disposition: attachment; filename=" + file_name);
      body.puts;
      body.puts([File.read(file_name)].pack("m*"));

      var mic = OpenSSL.Digest.SHA1.base64digest(body.string.gsub(
        /\n/,
        "\r\n"
      ));

      var pkcs7 = OpenSSL.PKCS7.sign(
        self._info.certificate,
        self._info.pkey,
        body.string
      );

      pkcs7.detached = true;
      var smime_signed = OpenSSL.PKCS7.write_smime(pkcs7, body.string);

      pkcs7 = OpenSSL.PKCS7.encrypt(
        [self._partner.certificate],
        smime_signed
      );

      var smime_encrypted = OpenSSL.PKCS7.write_smime(pkcs7);
      req.body = smime_encrypted.sub(/^.+?\n\n/m, "");
      var resp = http.request(req);
      var success = resp.code == "200";
      var mic_matched = false;
      var mid_matched = false;
      var disp_code = null;
      body = null;
      var smime, mail;

      if (success) {
        body = resp.body;
        smime = OpenSSL.PKCS7.read_smime("Content-Type: " + resp["Content-Type"] + "\r\n" + body);
        smime.verify([self._partner.certificate], Config.store);
        mail = new Mail(smime.data);

        mail.parts.each(function(part) {
          var options;

          switch (part.content_type) {
          case "text/plain":
            body = part.body;
            break;

          case "message/disposition-notification":
            options = {};

            part.body.to_s.lines.each(function(line) {
              if (/^([^:]+): (.+)$/.test(line)) options[$1] = $2
            });

            if (req["Message-ID"] == options["Original-Message-ID"]) {
              mid_matched = true
            } else {
              success = false
            };

            if (options["Received-Content-MIC"].start_with(mic)) {
              mic_matched = true
            } else {
              success = false
            };

            disp_code = options["Disposition"];
            success = disp_code.end_with("processed")
          }
        })
      };

      new Client.Result(success, resp, mic_matched, mid_matched, body, disp_code)
    })
  };

  return {Client: Client}
}()