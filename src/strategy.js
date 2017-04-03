import {
  Strategy
} from 'passport-strategy';
import * as speakeasy from 'speakeasy';

export default class PhoneCodeStrategy extends Strategy {
  constructor(options, verify) {
    const _options = options || {};
    const _verify = verify;

    if (!_options.secret) throw new Error('Phone Code authentication strategy requires an encryption secret');
    if (!_options.sendCode) throw new Error('Phone Code authentication strategy requires a sendToken function');

    _options.authPath = options.authPath || '/auth/phone';
    _options.codeRequestPath = options.codeRequestPath || '/auth/phone/code';

    super(_options, _verify);

    this.name = 'phone-code';
    // this._stageField = _options.stageField || 'stage';
    this._codeField = _options.codeField || 'code';
    this._phoneField = _options.phoneField || 'phone';
    this._displayNameField = _options.displayNameField || 'displayName';
    this._passReqToCallback = _options.passReqToCallback;
    this._sendCode = _options.sendCode;
    this._parseRequest = _options.parseRequest || this.lookup;
    this._secret = _options.secret;
    this._window = _options.window || 6;
    this._verify = _verify;
    this._options = _options;
  }

  authenticate(req, options) {
    const _self = this;
    // const stage = this.lookup(req, this._stageField);
    let phone = _self.lookup(req, _self._phoneField);
    let code = _self.lookup(req, _self._codeField);

    let displayName = _self.lookup(req, _self._displayNameField);

    if (phone && (typeof phone == 'string')) phone = phone.replace(/\D+/g, '');
    if (code && (typeof code == 'string')) code = code.replace(/\D+/g, '');

    if (phone) {
      if (code) {
        // stage 2 - filled phone and code
        let isValid = speakeasy.totp.verify({
          secret: phone + _self._secret,
          encoding: 'base32',
          token: code,
          window: _self._window
        });

        if (isValid) {
          const verified = (error, user, info) => {
            if (error) return _self.error(error);
            if (!user) return _self.fail(info);

            return _self.success(user, info);
          };

          let accessToken = '';
          let refreshToken = '';
          let profile = {
            provider: 'phone-code',
            id: phone,
            displayName: displayName || '',
            // name: {
            //   familyName: json.last_name || '',
            //   givenName: json.first_name || '',
            //   middleName: json.middle_name || ''
            // },
            // gender: json.gender || '',
            // emails: [{
            //   value: json.email || ''
            // }],
            // photos: [{
            //   value: imageUrl
            // }],
            // _raw: body,
            // _json: json
          };

          if (_self._passReqToCallback) {
            _self._verify(req, accessToken, refreshToken, profile, verified);
          } else {
            _self._verify(accessToken, refreshToken, profile, verified);
          }
        } else {
          return _self.fail({
            message: 'Invalid code'
          });
        }
      } else {
        // stage 1 - filled only phone
        let token = speakeasy.totp({
          secret: phone + _self._secret,
          encoding: 'base32'
        });
        _self._sendCode(phone, token, (err) => {
          if (err) return _self.error(err);
          _self.fail('Code sended', 401);
        });
      }
    } else {
      // no phone filled
      return _self.fail({
        message: `You should provide ${_self._phoneField}`
      });
    }
  } // authenticate

  lookup(req, field) {
    return (
      req.body && req.body[field] ||
      req.query && req.query[field] ||
      req.headers && (req.headers[field] || req.headers[field.toLowerCase()])
    );
  }
}
