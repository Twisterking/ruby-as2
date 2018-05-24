require("rack");
require("logger");
require("stringio");

AS2 = function() {
  MimeGenerator = function() {
    function Part() {
      this._parts = [];
      this._body = "";
      this._headers = {}
    };

    Part.prototype = {
      "[]": function(name) {
        this._headers[name]
      },

      set [](name, value) {
        this._headers[name] = value
      },

      get body() {
        return this._body
      },

      set body(body) {
        if (!this._parts.empty) throw "Cannot add plain budy to multipart";
        this._body = body
      },

      add_part: function(part) {
        if (!this._id) this.gen_id;
        this._parts.push(part);
        this._body = null
      },

      "multipart?": function() {
        !this._parts.empty
      },

      write: function(io) {
        this._headers.each(function(name, value) {
          if (multipart && /content-type/i.test(name)) {
            io.print(name + ": " + value + "; \r\n");
            io.print("\tboundary=\"----=_Part_" + this._id + "\"\r\n")
          } else {
            io.print(name + ": " + value + "\r\n")
          }
        });

        io.print("\r\n");

        if (this._parts.empty) {
          io.print(this._body, "\r\n")
        } else {
          this._parts.each(function(p) {
            io.print("------=_Part_" + this._id + "\r\n");
            p.write(io)
          });

          io.print("------=_Part_" + this._id + "--\r\n")
        };

        io.print("\r\n")
      }
    };

    Part.private;
    Part._counter = 0;

    Object.defineProperty(
      Part.prototype,
      "gen_id",

      {enumerable: true, configurable: true, get: function() {
        Part._counter++;
        this._id = Part._counter + "_" + Time.now.strftime("%Y%m%d%H%M%S%L");
        return this._id
      }}
    );

    return {Part: Part}
  }();

  function Server(block) {
    this._block = block;
    this._info = Config.server_info
  };

  Server.HEADER_MAP = {
    To: "HTTP_AS2_TO",
    From: "HTTP_AS2_FROM",
    Subject: "HTTP_SUBJECT",
    "MIME-Version": "HTTP_MIME_VERSION",
    "Content-Disposition": "HTTP_CONTENT_DISPOSITION",
    "Content-Type": "CONTENT_TYPE"
  };

  Server.prototype = {
    get logger() {
      return this._logger
    },

    set logger(logger) {
      this._logger = logger
    },

    call: function(env) {
      if (env["HTTP_AS2_TO"] != this._info.name) {
        return this.send_error(
          env,
          "Invalid destination name " + env["HTTP_AS2_TO"]
        )
      };

      var partner = Config.partners[env["HTTP_AS2_FROM"]];

      if (!partner) {
        return this.send_error(
          env,
          "Invalid partner name " + env["HTTP_AS2_FROM"]
        )
      };

      var smime_data = new StringIO;

      Server.HEADER_MAP.each(function(name, value) {
        smime_data.puts(name + ": " + env[value])
      });

      smime_data.puts("Content-Transfer-Encoding: base64");
      smime_data.puts;
      smime_data.puts([env["rack.input"].read].pack("m*"));
      var smime = OpenSSL.PKCS7.read_smime(smime_data.string);

      var smime_decrypted = smime.decrypt(
        this._info.pkey,
        this._info.certificate
      );

      smime = OpenSSL.PKCS7.read_smime(smime_decrypted);
      smime.verify([partner.certificate], Config.store);
      var mic = OpenSSL.Digest.SHA1.base64digest(smime.data);
      var mail = new Mail(smime.data);

      var part = (mail.has_attachments ? mail.attachments.find(function(a) {
        a.content_type == "application/edi-consent"
      }) : mail);

      if (this._block) {
        try {
          this._block.call(part.filename, part.body)
        } catch (e) {
          return this.send_error(env, $!.message)
        }
      };

      this.send_mdn(env, mic)
    }
  };

  Server.private;

  Server.prototype.logger = function(env) {
    this._logger = this._logger || new Logger(env["rack.errors"])
  };

  Server.prototype.send_error = function(env, msg) {
    this.logger(env).error(msg);
    this.send_mdn(env, null, msg)
  };

  Server.prototype.send_mdn = function(env, mic, failed) {
    if (typeof failed === 'undefined') failed = null;
    var report = new MimeGenerator.Part;
    report["Content-Type"] = "multipart/report; report-type=disposition-notification";
    var text = new MimeGenerator.Part;
    text["Content-Type"] = "text/plain";
    text["Content-Transfer-Encoding"] = "7bit";
    text.body = "The AS2 message has been received successfully";
    report.add_part(text);
    var notification = new MimeGenerator.Part;
    notification["Content-Type"] = "message/disposition-notification";
    notification["Content-Transfer-Encoding"] = "7bit";

    var options = {
      "Reporting-UA": this._info.name,
      "Original-Recipient": "rfc822; " + this._info.name,
      "Final-Recipient": "rfc822; " + this._info.name,
      "Original-Message-ID": env["HTTP_MESSAGE_ID"]
    };

    if (failed) {
      options["Disposition"] = "automatic-action/MDN-sent-automatically; failed";
      options["Failure"] = failed
    } else {
      options["Disposition"] = "automatic-action/MDN-sent-automatically; processed"
    };

    if (mic) options["Received-Content-MIC"] = mic + ", sha1";

    notification.body = options.map(function(n, v) {
      n + ": " + v
    }).join("\r\n");

    report.add_part(notification);
    var msg_out = new StringIO;
    report.write(msg_out);

    var pkcs7 = OpenSSL.PKCS7.sign(
      this._info.certificate,
      this._info.pkey,
      msg_out.string
    );

    pkcs7.detached = true;
    var smime_signed = OpenSSL.PKCS7.write_smime(pkcs7, msg_out.string);
    var content_type = smime_signed[/^Content-Type: (.+?)$/m, 1];
    smime_signed.sub(/\A.+?^(?=---)/m, "");
    var headers = {};
    headers["Content-Type"] = content_type;
    headers["MIME-Version"] = "1.0";
    headers["Message-ID"] = "<" + this._info.name + "-" + Time.now.strftime("%Y%m%d%H%M%S") + "@" + this._info.domain + ">";
    headers["AS2-From"] = this._info.name;
    headers["AS2-To"] = env["HTTP_AS2_FROM"];
    headers["AS2-Version"] = "1.2";
    headers["Connection"] = "close";
    [200, headers, ["\r\n" + smime_signed]]
  };

  return {Server: Server}
}()