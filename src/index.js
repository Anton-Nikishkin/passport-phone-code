import {
  Strategy
} from 'passport-strategy';

export default class PhoneCodeStrategy extends Strategy {
  constructor(_options, _verify) {
    const options = _options || {};
    const verify = _verify;

    options.authPath = options.authPath || '/auth/phone';
    options.codeRequestPath = options.codeRequestPath || '/auth/phone/code';

    super(options, verify);

    this.name = 'phone-code';
    this._codeField = options.codeField || 'code';
    this._phoneField = options.phoneField || 'phone';
    this._passReqToCallback = options.passReqToCallback;
  }

  authenticate(req, options) {
    const phone = this.lookup(req, this._phoneField);
    const code = this.lookup(req, this._codeField);

    if (!phone) return this.fail({
      message: `You should provide ${this._phoneField}`
    });
    if (!code) return this.fail({
      message: `You should provide ${this._codeField}`
    });

    const verified = (error, user, info) => {
      if (error) return this.error(error);
      if (!user) return this.fail(info);

      return this.success(user, info);
    };

    if (this._passReqToCallback) {
      this._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      this._verify(accessToken, refreshToken, profile, verified);
    }

  }

  lookup(req, field) {
    return (
      req.body && req.body[field] ||
      req.query && req.query[field] ||
      req.headers && (req.headers[field] || req.headers[field.toLowerCase()])
    );
  }
}
