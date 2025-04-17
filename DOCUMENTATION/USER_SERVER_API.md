# AuthMatter User-Server API

Many design considerations collected in this document are not implemented yet.



## Notation Conventions

- Command argv field name ending with question mark (`?`) means optional.
- Indent means required only if an optional field is supplied.
- Error code rages:
  - 1-99: Shared public errors
  - 100-999: Errors specific to this command
  - 10000-Inf: Errors happened in control center and not in commands
- User (partial: a, b?) means only certain `a` and `b` fields of User model need to be supplied, and `b` is optional.


## Public Errors

| Error Number | Description                    |
| ------------ | ------------------------------ |
| 1            | Database connection error      |
| 2            | No privilege to invoke command |
| 3            | No access to target source     |


## Admin Namespace

### admin.add_domestic_user
argv:
- String `username` (without domain)
- String `display_name?` (default: same to username)
- bool `is_admin?` (default: `false`)

stdout:
- User `user_obj`

Errors:
- 101: Invalid username
- 102: Given username is taken

### admin.get_user_by_uid
argv:
- int `uid`

stdout:
- User `user_obj`

Errors:
- 101: Invalid UID

### admin.list_all_users
argv:
- bool `is_paged?` (default: `false`)
  - int `page`

stdout:
- Array[User] `users`

Errors: none

### admin.set_user_frozen_state
argv:
- int `uid`
- bool `is_frozen`

stdout: User

Errors:
- 101: Invalid UID

### admin.forget_roaming_user
argv:
- int `uid`

stdout: User

Errors:
- 101: Invalid UID
- 102: User is not roaming

### admin.change_user_info
argv: User (partial: uid, username?, display_name?)

stdout: User

Errors:
- 101: Invalid UID
- 102: Invalid UID

## User Namespace

### user.whoami
argv: none

stdout: User

Errors: none


### user.add_credential
argv:
- AbstractCredential `credential`

stdout: AbstractCredential

Errors:
- 1: Upstream database error
- 2: 3
