
## Run Tang Server
```shell
docker run -d -p 8080:80 --name tang \
-v tang-db:/var/db/tang \
 malaiwah/tang
```

### Extract Thumbprint from Tang server
#### Install
- jq
- jose

#### Run
```shell
curl -s http://localhost:8080/adv | jq -r '.payload' | base64 --decode | jq '.keys[0]' | jose jwk thp -i -
```

## Run Example Encrypt -> Decrypt
```shell
cd cmd
./test_run.sh
```


eyJhbGciOiJFQ0RILUVTIiwiY2xldmlzIjp7InBpbiI6InRhbmciLCJ0YW5nIjp7InVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImFkdiI6eyJrZXlzIjpbeyJhbGciOiJFUzUxMiIsImNydiI6IlAtNTIxIiwia2V5X29wcyI6WyJ2ZXJpZnkiXSwia3R5IjoiRUMiLCJ4IjoiQVJXTjZSMm45bVliLW8yRE1TRGNKQ2dTX3hXc1MwT1lKMHNvTXJxMEwyc1E2WU41RmhGNzNxQVpiUkhSSTNxQVpsMm1WOXQ2N2JUOHhsdl9Ed2VEUXl4bCIsInkiOiJBZFVjUVgycUdINEtuTDcxOHV3c1M2b1c2Z1Z0RU1rLXpSMDNMOG44R29LeVluNk9qSVdoUlJUamZDaW5ndmFQTlF3OWhJNXo4T1ZseFQ4d3g2amRSc01KIn0seyJhbGciOiJFQ01SIiwiY3J2IjoiUC01MjEiLCJrZXlfb3BzIjpbImRlcml2ZUtleSJdLCJrdHkiOiJFQyIsIngiOiJBV3dlUnNDYVdYS011Wm9aSVRaalBfaU14cEtYdTdnQ0E3TFNwZmlfakJXN0FXNXY5M0oxUnFab0lncXFOdEVYRUxXeTB3UDc3WWp0RndJTml4RHMtTnY2IiwieSI6IkFjOW0xTEpPaURlV251M1ZQaHhzbmRrUVBjX0wyQmtkVXIxV2JCcEdwZEE0cDJnNUVkeTVGbzAtODI1cG1mUUM4TnV0MHpDSU51dlR0S3lremkzVFB5RUYifV19fX0sImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBR1VIVmFyUVlGN1VhVW92engyMzc2VlNrN2g1cG1HWTV5a2poNzF2UFdEVVFERHRRUjdSNnJQUUliR2h3a2hLdWhHMXBEVmhtS1psQ3JyNHRrb1Q5WVJ1IiwieSI6IkFSb2ZHWFVlWjZhaTduMFUxOS1ZaTJGa2lhenRlVlppb2xXd1IzVVdfMExSRWt3Mm9ZQ3d0TFZCSHpoRjgtTWV5amRTUXlSS2RRbl9feEVsRW5vbkxXVTUifSwia2lkIjoieDNHOU9tLWFGNzNtX29hN19rT3FjR3FhMW1Zc0tGeFM3azE5UzNqVWxzMCJ9..xl2x0Sjr32-i4-A1.-rXh3X8btog9pXWL_IxFNS8nELBN_6CA8KDeW5BtOrhUOMjJYWUeiu56EV3VE13zrmwSYcaDBM7sBr_waZEIDbESRUIjhnm-dso-VUwjO1dEmFPgsI8oyBjCVastNjBwgrdUUEjhblRM7NbhJyi1N4nkJJzdJeL64934mIJzrtdKAVwqVBUNX6R9ghjK4VhA7agyTQdUGPMUVaqJxn1MmwIPuSGToFqlzrLRsaUO2YovDkJQ1dn7VxlWC7VfXvUUKFhVQ1qebKRgwTDsHZPG57rNr5Zu2tXBZDs09Eig0_WczUc3TZVJ9-R8y7kQ2Hvl_eSzQ92XbCwzS2RaqHY_eb0GdaaWIpn53wCec14UVZwwh502SxFgjDxH-QO6T5LtTZ71GYlPZRthbBlmveF67B1iIwQd1NzzoQquGaPTVn98x10_rmJVqbXq8mlX9kexIpG5-C4J8w94UHN1lHZG3qipmfe3yRhm5V4iTOokpX9_D3b5ckPS5CspO5HVTkGBjoMlNxJhyfzsGeSg2vKPWwXLf1HYw9vzwigkMdB2yriORws1YI7HV5XsBlnUJMNLtN5l-qESM3DAwGuvt6DmYc_ADnNPSb3NILUAA9g208pjSeclm_GtT-JPiqEklHWU4FFSeoX4w5lWQm2er99EuUir8LD-66YBtAr3hQuAGP-Pz8wPwFMhYI0FA9reADQ6WSWxDnhtXrICHOdqaPV09y0MC5x4WshcyC7JOPS0Iv6EAiXRGc6PpfQPQckg5O3MOyhxWm5_dybaEI0is1mmc9Rx5oHS3xXWLc9z4Qkeem-BLMQyimH3u9eCNyr57GW92E5aQWtAFa460mX6axy8zaDjMh3_XrQx8T6Z37A5vBLkJehglDCbxrmNN_rmg_EX5CWprRcneioeOc76MGPZM6qT7nFojkZqzTz7sJiyTZrvDGNSAAAx0ipUZffsg2YqpUIiUYuoVVeDbVA-4YPEKLlCvJDTqBgrAnNmQluzBwOSdGPHzrz7j-tZEltpjBTySv8xP0G-7dOsiNIqopr2Ul0MhsLWMBa9HArLOctCvaxN8V4riT8BeLI4IXoV4SP2s26Emnj7EtsgTDSfKTmSZbon3LiC7TKTV0_-bgHpoOf-z2MBv0H-KPEudp4jM0LbwqPCy5y_0BH9nfVVKozcXbtx1bfShnTm862qrwr0p0OwABci72OTbYX3914_K0rO57nSAdEUSFR-bwzZYAf13F4z_W2V2X_3ZDms0Rd67_UOw1PhtQFJpw1HlPGdB93nQf_mLFmfU4R3BFi2kfVMG-5jkQ_sWe6airPs_6kyZ_BPsUnALSeHk-bxR3zzZRnhp6yxcE0z3oYEnIAgCrepv8GzvZZoapMJ0K6BSgtimaIyImLVHH9UGEkBda9zR-Sv7AobFcnWKs6YGeyMskFKVi6XjcbGMTpvGi6Rri_sMne4aM1Dg5kTdjZJ6a0zeNRJSr_28WUGPN5CMr9yKehxOFEd5zfC-XIFX3Y0Bnp9GXuLEDwpe_QwL99iqEXbSWw5xdVisSzwP4WSIQBI6yKQIPkkm5K2Y5H6a8kGqgR0-q4zxjNaIG9hwKYieYRKe9GqdejPsFzAnO9xg2hvDpobqEX7hRHkcI4rT2M-crJepRXbnDmFegRDVT6AxKkCgFu1j2rWlQ97UUzBUklu9M9usmgXSWLPRK310AbxopUMbPmvjrVMKYPVxD3Cv9p8jDpD9m9FBP3waRG-IF2UgCE5791o-XBEM7Kv3QDS02XCOPN5DmmrWPhlD_H4H1OG8F8a5kbdCh-u758F4WXJ55dKWHoQakgBG8ww4CSBnxBu4XV6vK-7LeANVZCaWcejRBJ3cYm2zxxDFzADajjDcrjn-OCjEGYqhzAbVPLM2uNWT9cHgKED4uSCcel6hvIbra-Zyegp7tcE_rCp_5a6AmuZgUwtbGDpimShn8enjbehn5XJoI4hcYGq7Z_XErPjtVZE3TLw3w1839LaCH1GNIpdiRZhBJ0x2D_gPy0RKLuTjnhNiLGxhHdFK6TntjZPi1PED-rkwtSaUdgkVfwSu_O4uiGJwoCFAJ98j9sWu0vxc0MHdk35I4IXHCuMAo5EuRM6XfA96f7PPQkueQJvukqzQS3O-TurZGv_vvMC-H6tAP7zadcClv0BR6-5CUkljvjR8k61oGpnWtisnNs.zKiMoLveyttwI923nFJVcQ