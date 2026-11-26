-- AWS SNS verification.
--
-- SNS does not sign with a shared secret. Each message carries an RSA signature
-- over a canonical form of its JSON envelope, checked against a certificate AWS
-- publishes, and SNS delivers nothing until the endpoint confirms the
-- subscription by fetching the SubscribeURL of the confirmation message.
--
-- sns_auto_confirm is that decision, per endpoint: confirm the subscription
-- after the signature verifies, or keep the confirmation as evidence for
-- someone who holds the key. sns_topics pins the topics this endpoint accepts;
-- empty means any topic whose signature verifies, which is only reasonable for
-- an operator who reads the log. The signature proves AWS sent the message, not
-- that the topic belongs to you — that is what this list is for.

alter table endpoint
    drop constraint verify_needs_secret,
    drop constraint endpoint_verify_check;

alter table endpoint
    add constraint endpoint_verify_check
        check (verify in ('none', 'github', 'meta', 'stripe', 'generic-hmac', 'sns')),
    -- SNS has no shared secret to store, so the old "every profile needs one"
    -- rule would make the profile impossible to select.
    add constraint verify_needs_secret
        check (verify in ('none', 'sns') or verify_secret is not null),
    add column sns_auto_confirm boolean not null default false,
    add column sns_topics text[] not null default '{}';
