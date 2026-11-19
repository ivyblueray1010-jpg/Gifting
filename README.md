# G TOP staging upgrade

This is a staging/test starter, not production financial infrastructure.

## Included
- Customer registration and login
- Admin login
- Bronze/Silver/Gold plan ranges and 4–14 day duration
- Test-only deposit records and admin review
- Test-only investments and withdrawal requests
- Customer history and admin overview
- Admin customer suspension, plan creation, performance entries and audit log
- PostgreSQL-backed sessions and data

## Important safety limits
- No payment gateway, wallet integration, blockchain verification, custody, or real transfer is implemented.
- Test deposit approvals only create simulated test balance.
- Withdrawal approvals do not send funds.
- Performance is entered manually by an administrator and should only reflect evidenced actual performance.
- Do not use this staging app to accept customer money or advertise investment returns.
- Before any live financial use, obtain independent legal/compliance review, security audit, KYC/AML controls, custody and payment architecture, and operational approval.

## Render
Deploy this folder as a separate Render Blueprint from the `gtop-upgrade` branch. The `render.yaml` creates a new service named `gtop-upgrade` and a new database named `gtop-upgrade-db`. It does not reference the existing production database.

When Render asks for `ADMIN_EMAIL` and `ADMIN_PASSWORD`, set a dedicated strong admin email and password. Never put secrets in GitHub. Set the password in Render environment variables only.
