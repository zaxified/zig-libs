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

// Passphrase-protected fixtures (2026-10-09), for the encrypted-container
// loaders. Recipe (OpenSSH 10.2p1; 4 bcrypt rounds so a test run stays fast):
//   ssh-keygen -t ed25519 -a 4 -N 'zig-libs test passphrase' -C enc-ed25519 -f k_ed_ctr
//   ssh-keygen -t ecdsa -b 256 -a 4 -N 'zig-libs test passphrase' -C enc-ecdsa -f k_ec_ctr
//   ssh-keygen -t ed25519 -a 4 -Z aes256-cbc -N 'zig-libs test passphrase' -C enc-ed25519-cbc -f k_ed_cbc
pub const enc_passphrase = "zig-libs test passphrase";

pub const ed25519_enc_ctr_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAACp5Po6
    \\wevGELav/wD7UAAAAABAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPtX6m7TBluXaQ/3
    \\oT9G+7lKQo/fq9Mqlnkjj/KGJ0VVAAAAkOx+aNW8mTM8M9KzpdLxcQdmR9w85Uhs37Zg1i
    \\xAgr2KFO//4wLPbWK0J3K10ven/2dO3MCO2yL0iRnwFiaYJucukNNpxv3UmSdfQOSEcSRz
    \\YTvK0xgucBaKoKbS9aDuTPBmuCokpsO0/O1AzLdfsrmCPAU2jVY/pfFOIiXj9rZQ8KjpYm
    \\OA4vdJYwKlwySnew==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
pub const ed25519_enc_ctr_pub_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIPtX6m7TBluXaQ/3oT9G+7lKQo/fq9Mqlnkjj/KGJ0VV";

pub const ecdsa_p256_enc_ctr_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA1DBK1M7
    \\EnXY7RRr1mqpyKAAAABAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
    \\dHAyNTYAAABBBFoWEw5n9h7aJ0kLFCysEaq1IKFIGfRcrFuFpL+qfZ6jI+a0l15pxr6EZF
    \\peyeMTcDCCQiDMCOdQ/OFYmoh62NcAAACwBSz0fiZ0xEIxZLqpf4NpDosv0eG9vlM9ZIpL
    \\Op6NdSLjQw3Xz9+s69z1WKZgY/KfwwSCJcxWpa9HtTfOobTTyzlwF1xkvtxXFXH4BubDf7
    \\r9vqcznfeIGBvVCrUAdprJ3r/ox8/v5OIGScuM1h8NuB0XJGIWayWU0KTIiHOJkSFmfxEC
    \\YtB92nKowk255cZlVOJNE2pyYYDe8bO4YvdwG1tQ6PBzpO+rx+STEXj/+18=
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
pub const ecdsa_p256_enc_ctr_pub_b64 = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFoWEw5n9h7aJ0kLFCysEaq1IKFIGfRcrFuFpL+qfZ6jI+a0l15pxr6EZFpeyeMTcDCCQiDMCOdQ/OFYmoh62Nc=";

pub const ed25519_enc_cbc_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABBLHD6R+D
    \\8SdiV15fyIAeE7AAAABAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEq8T4lwqJnsth2z
    \\VWfVYPezBwn3eAW27HziuxxfgpFSAAAAoDVXlMl5rpmjHKFpZzwbUMKw8A4ZcF4kICbC4Z
    \\iJ7UgZj027jGchq3b5VVvF2ZWXWKT9HhLSSo1LRaOv2Efb4vqY3AHhH1FcGyihUR0XARwU
    \\e91EiUiTliYYKN78YzxMUv6E1hOlp+mmHzX5F2fTwJQoRsl2SE6kKXKfaaS+EybVIhFvOC
    \\wXgPSCblxoVA6t/fvIytLj6soZp1GfHSiCjk8=
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
pub const ed25519_enc_cbc_pub_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIEq8T4lwqJnsth2zVWfVYPezBwn3eAW27HziuxxfgpFS";

pub const ecdsa_p384_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
    \\1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSxj+euKAsyQjR6bVdXkUiJb4O5Oav8
    \\xmmrwclXZijLFShdQnpu0ggC0260/kV8X2hFixCHj8S82L7FHQv5/ajrTbRM3dr4Raw2Ny
    \\n1XA+j9ZbD8A9jAcdgquI33GtpB/wAAADoiRzE0okcxNIAAAATZWNkc2Etc2hhMi1uaXN0
    \\cDM4NAAAAAhuaXN0cDM4NAAAAGEEsY/nrigLMkI0em1XV5FIiW+DuTmr/MZpq8HJV2Yoyx
    \\UoXUJ6btIIAtNutP5FfF9oRYsQh4/EvNi+xR0L+f2o6020TN3a+EWsNjcp9VwPo/WWw/AP
    \\YwHHYKriN9xraQf8AAAAMQCMj3GmquDQTSNyJ6FMKYpSBIv2NELSZAcIVh5bk9ClWvfgPq
    \\MoljAfP2kBqnYw8zIAAAAZemlnLWxpYnMtc3NoLXRlc3QtZml4dHVyZQECAwQFBg==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
pub const ecdsa_p384_pub_b64 =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBLGP564oCzJCNHptV1eRSIlv" ++
    "g7k5q/zGaavByVdmKMsVKF1Cem7SCALTbrT+RXxfaEWLEIePxLzYvsUdC/n9qOtNtEzd2vhFrDY3" ++
    "KfVcD6P1lsPwD2MBx2Cq4jfca2kH/A==";

pub const ecdsa_p521_key =
    \\-----BEGIN OPENSSH PRIVATE KEY-----
    \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
    \\1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQBDt7L6tnuRt3frOAZ6Z8X3u2W1vLL
    \\uKZI5kc+/xnYn7qsXneC+sDy3YNLuzsZsfyoZS3JKD7VihQk1wtFxRkqjeEBJq646zKzte
    \\0XosxIUCzPSfUr6ZIm1abn88mFbWPMB2hhfHPCT28baddNhOJeNV+RXRFngySHdaNyqYYI
    \\3VIKn2AAAAEYtlKHj7ZSh48AAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
    \\AAAIUEAQ7ey+rZ7kbd36zgGemfF97tltbyy7imSOZHPv8Z2J+6rF53gvrA8t2DS7s7GbH8
    \\qGUtySg+1YoUJNcLRcUZKo3hASauuOsys7XtF6LMSFAsz0n1K+mSJtWm5/PJhW1jzAdoYX
    \\xzwk9vG2nXTYTiXjVfkV0RZ4Mkh3WjcqmGCN1SCp9gAAAAQgCgkg/wLvtTi5rcTT74RZF3
    \\u7CScLr1aWTAYQY76+bF1HPodQFnLMgE3gVgrW8S8a21I2ptvUEXqk7NXnNfvc1LAQAAAB
    \\l6aWctbGlicy1zc2gtdGVzdC1maXh0dXJlAQ==
    \\-----END OPENSSH PRIVATE KEY-----
    \\
;
pub const ecdsa_p521_pub_b64 =
    "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAEO3svq2e5G3d+s4Bnpnxfe" ++
    "7ZbW8su4pkjmRz7/Gdifuqxed4L6wPLdg0u7Oxmx/KhlLckoPtWKFCTXC0XFGSqN4QEmrrjrMrO1" ++
    "7ReizEhQLM9J9SvpkibVpufzyYVtY8wHaGF8c8JPbxtp102E4l41X5FdEWeDJId1o3KphgjdUgqf" ++
    "YA==";
