// SPDX-License-Identifier: MIT

//! Throwaway, purpose-generated host-key fixtures (ssh-keygen -N "" -C
//! "zig-libs-ssh-test-fixture") for `server.zig`'s tests and
//! `stackprobe_test.zig`. Never used outside the tests.

pub const ed25519_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    \\QyNTUxOQAAACAbXh+0xX5CqQGbodRtCemLNds0YSHGSbliNLhNrJtVowAAAKBLNuLfSzbi
    \\3wAAAAtzc2gtZWQyNTUxOQAAACAbXh+0xX5CqQGbodRtCemLNds0YSHGSbliNLhNrJtVow
    \\AAAEAT1J99c1Kuebn+/em6EEfb1f4ugX6800dEkxIiGL7b1hteH7TFfkKpAZuh1G0J6Ys1
    \\2zRhIcZJuWI0uE2sm1WjAAAAGXppZy1saWJzLXNzaC10ZXN0LWZpeHR1cmUBAgME
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
pub const ed25519_pub_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIBteH7TFfkKpAZuh1G0J6Ys12zRhIcZJuWI0uE2sm1Wj";

pub const rsa_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
    \\NhAAAAAwEAAQAAAQEAsTT0LyOIfVddUOIh7ipZkRnSCOkePGSxxPc/2vu1OlM+JT+igdyT
    \\b9h42yQTw9vG2P2uStEmiaasYGAjENl+eK1bOzTWMUwlBUi4zVXN9CxxWUZmLl59u9Y9uz
    \\uM0wDMdEWSQ5iLSOfcIHMnJwy5tKBZj71ejcNFkfAlcN8kT9jR1eqlMBfhH8OJLRLUbLXr
    \\Jlnjyi9Ao6Ki3HoP+65KZKCma0powh1Vo0crCNc0cYdG4vnoBUYOvg7iL3GtW99Yg8pg7z
    \\h7GAq2+gKPnCEoZMjOu+NZ4yQw8dW25SeahszGNxLRteoek6d9lJHvbtrdzMLE/ci7/Pe0
    \\cveoowVLwwAAA9DfoGmR36BpkQAAAAdzc2gtcnNhAAABAQCxNPQvI4h9V11Q4iHuKlmRGd
    \\II6R48ZLHE9z/a+7U6Uz4lP6KB3JNv2HjbJBPD28bY/a5K0SaJpqxgYCMQ2X54rVs7NNYx
    \\TCUFSLjNVc30LHFZRmYuXn271j27O4zTAMx0RZJDmItI59wgcycnDLm0oFmPvV6Nw0WR8C
    \\Vw3yRP2NHV6qUwF+Efw4ktEtRstesmWePKL0CjoqLceg/7rkpkoKZrSmjCHVWjRysI1zRx
    \\h0bi+egFRg6+DuIvca1b31iDymDvOHsYCrb6Ao+cIShkyM6741njJDDx1bblJ5qGzMY3Et
    \\G16h6Tp32Uke9u2t3MwsT9yLv897Ry96ijBUvDAAAAAwEAAQAAAQAtWwZcwlV+70t9FkPk
    \\94XxM5CkozYP8x3k8fuwCti50vCHDCCF6HT8HYXhYPyGFsxwYY2orJuWg8h+6lxPRbuvG3
    \\/MSZvBBmI7Vf+m3p1WL8HbPb+NgrXfy9gFAhrrLrslz2C+WF7eDCo1TAPrZMBrUNdbiPaY
    \\hjBaSALtPs/Gd6Tl34dr7sf0egcJhEInYtYV5HwOMvVlyZ4oQWejvV9mr9dPd/46YZtAno
    \\JktXCjtkqAoWClgp1QUb5vbb+HMtuzHVFUtzyQ3iTFA4Nw0uMuumNyNgHIPIEoNZrK2ugU
    \\ylXZOX8PSJuD4kXvd6Pa9cyuQKsqGuS3gxy0dx3Sa9IxAAAAgH/wPnFcrOrAPoLklNtk/b
    \\mudndObm73psJlWpiqv5R6Ydxa3Lnk4pcijFx/QoddlEHPKXEsCXXSwDyQSkPzY6/Zm/Gh
    \\lQNpJpXfvF237eJ4N3/x4FdvP30XV2LM15P16a9rTGDU9/lfspx3DWskKDvMN8XjSoEleE
    \\2D6w732aSfAAAAgQDnZIzPFadc1axuEv7Duj2KsVEGoYHK6zcJuhMtlelqi+nlgx9roPSS
    \\oXxc5wQEG/tPh7pTfETpp4OTAcih2e1bHy1RjLjuDa6ClXkYt3ex7IfQ9FCly/uHNKPBJi
    \\EKR8mqwC+FuAs0U+7LnNLRI7FKreiwHGZ7KnjBCPZyYJoF/QAAAIEAxA0+QV7uVgb4MWvk
    \\VORUlLPAZu5kk3gnKl3mE7yIHYiSJ+8bfM2mT2lNALDcO9LsO94S2AoZbc+nEvfgEGhMuO
    \\Yb4M407p9NvfmEe2+hUBuPjlRTLzAPw+MAhvg7K+uV0tsbNiAAQ9Piquu6D9D7fWMU6LtR
    \\+MAP9t6jMgYUZL8AAAAZemlnLWxpYnMtc3NoLXRlc3QtZml4dHVyZQEC
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
pub const rsa_pub_b64 =
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQCxNPQvI4h9V11Q4iHuKlmRGdII6R48ZLHE9z/a+7U6" ++
    "Uz4lP6KB3JNv2HjbJBPD28bY/a5K0SaJpqxgYCMQ2X54rVs7NNYxTCUFSLjNVc30LHFZRmYu" ++
    "Xn271j27O4zTAMx0RZJDmItI59wgcycnDLm0oFmPvV6Nw0WR8CVw3yRP2NHV6qUwF+Efw4kt" ++
    "EtRstesmWePKL0CjoqLceg/7rkpkoKZrSmjCHVWjRysI1zRxh0bi+egFRg6+DuIvca1b31iD" ++
    "ymDvOHsYCrb6Ao+cIShkyM6741njJDDx1bblJ5qGzMY3EtG16h6Tp32Uke9u2t3MwsT9yLv8" ++
    "97Ry96ijBUvD";

pub const ecdsa_p256_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
    \\1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQhQ4cvIpboplGvcFaBMW/jRedkPGqA
    \\788x4sH6ZuTBr50cBzpO6S9EcxxJZRQ1ECG/aPPtAXnR6u2RRv87CKlWAAAAuOihgOPooY
    \\DjAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCFDhy8iluimUa9w
    \\VoExb+NF52Q8aoDvzzHiwfpm5MGvnRwHOk7pL0RzHEllFDUQIb9o8+0BedHq7ZFG/zsIqV
    \\YAAAAgTLRrzZQ6+kQBqIBZfCRC//prU3BuTHo0BDNBErPc11cAAAAZemlnLWxpYnMtc3No
    \\LXRlc3QtZml4dHVyZQECAwQFBgc=
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
pub const ecdsa_p256_pub_b64 =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCFDhy8iluimUa9wVoExb+NF" ++
    "52Q8aoDvzzHiwfpm5MGvnRwHOk7pL0RzHEllFDUQIb9o8+0BedHq7ZFG/zsIqVY=";
