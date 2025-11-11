# TODOs

## Hardening / User security

- [X] Remove default users with unsafe pw's
- [X] Users should not be able to guess note id's - add public flag at the very least
- [X] Add brute-force protection (Flask-Limiter)
- [ ] Improve Content-Security-Policy with use of nonces
- [X] Implement node deletion
- [X] Implement user deletion
- [ ] Admin can change password

## Vulnerability

- [ ] Research shell injection with image uploading
- [ ] Leak admin credentials on db initialization
- [ ] Research root access vulnerability for admin panel
