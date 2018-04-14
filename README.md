jCasbin
====

[![Build Status](https://travis-ci.org/casbin/jcasbin.svg?branch=master)](https://travis-ci.org/casbin/jcasbin)
[![Coverage Status](https://coveralls.io/repos/github/casbin/jcasbin/badge.svg?branch=master)](https://coveralls.io/github/casbin/jcasbin?branch=master)
[![Release](https://img.shields.io/github/release/casbin/jcasbin.svg)](https://github.com/casbin/jcasbin/releases/latest)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/casbin/lobby)
[![Patreon](https://img.shields.io/badge/patreon-donate-yellow.svg)](http://www.patreon.com/yangluo)
[![Sourcegraph Badge](https://sourcegraph.com/github.com/casbin/jcasbin/-/badge.svg)](https://sourcegraph.com/github.com/casbin/jcasbin?badge)

**Note**: This project is a Java port of the original Golang [Casbin](https://github.com/casbin/casbin).

![casbin Logo](casbin-logo.png)

jCasbin is a powerful and efficient open-source access control library for Java projects. It provides support for enforcing authorization based on various [access control models](https://en.wikipedia.org/wiki/Computer_security_model).

## Supported models

1. [**ACL (Access Control List)**](https://en.wikipedia.org/wiki/Access_control_list)
2. **ACL with [superuser](https://en.wikipedia.org/wiki/Superuser)**
3. **ACL without users**: especially useful for systems that don't have authentication or user log-ins.
3. **ACL without resources**: some scenarios may target for a type of resources instead of an individual resource by using permissions like ``write-article``, ``read-log``. It doesn't control the access to a specific article or log.
4. **[RBAC (Role-Based Access Control)](https://en.wikipedia.org/wiki/Role-based_access_control)**
5. **RBAC with resource roles**: both users and resources can have roles (or groups) at the same time.
6. **RBAC with domains/tenants**: users can have different role sets for different domains/tenants.
7. **[ABAC (Attribute-Based Access Control)](https://en.wikipedia.org/wiki/Attribute-Based_Access_Control)**: syntax sugar like ``resource.Owner`` can be used to get the attribute for a resource.
8. **[RESTful](https://en.wikipedia.org/wiki/Representational_state_transfer)**: supports paths like ``/res/*``, ``/res/:id`` and HTTP methods like ``GET``, ``POST``, ``PUT``, ``DELETE``.
9. **Deny-override**: both allow and deny authorizations are supported, deny overrides the allow.
10. **Priority**: the policy rules can be prioritized like firewall rules.

## License

This project is licensed under the [Apache 2.0 license](https://github.com/casbin/casbin/blob/master/LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.
- https://github.com/casbin/casbin/issues
- hsluoyz@gmail.com
- Tencent QQ group: [546057381](//shang.qq.com/wpa/qunwpa?idkey=8ac8b91fc97ace3d383d0035f7aa06f7d670fd8e8d4837347354a31c18fac885)

## Donation

[![Patreon](https://hsluoyz.github.io/donation/patreon.png)](http://www.patreon.com/yangluo)

![Alipay](https://hsluoyz.github.io/donation/donate_alipay.png)
![Wechat](https://hsluoyz.github.io/donation/donate_weixin.png)
