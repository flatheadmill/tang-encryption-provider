CLEVIS_DEFAULT_THP_ALG=S256

cfg='{"url":"http://tang:8080","thp":"o6U9qKv0_XdugefJV3q_NknYTY4Xgw27kcUnErkrVCY"}'
thp="$(jose fmt -j- -Og thp -Su- <<< "$cfg")"
url="$(jose fmt -j- -Og url -u- <<< "$cfg")"

jws="$(curl -sfg "$url/adv/$thp")"
jwks="$(jose fmt --json="${jws}" -Og payload -SyOg keys -AUo- 2>/dev/null)"

ver="$(jose jwk use -i- -r -u verify -o- <<< "$jwks")"

jose jws ver -i "$jws" -k- -a <<< "$ver" || exit 1

jose jwk thp -i- -f "${thp}" -a "${CLEVIS_DEFAULT_THP_ALG}" -o /dev/null <<< "$ver" || exit 1

enc="$(jose jwk use -i- -r -u deriveKey -o- <<< "$jwks")"

jose fmt -j "$enc" -Og keys -A || enc="{\"keys\":[$enc]}"

jwk="$(jose fmt -j- -Og keys -Af- <<< "$enc")" || exit 1

jwk="$(jose fmt -j- -Od key_ops -o- <<< "$jwk")"
jwk="$(jose fmt -j- -Od alg -o- <<< "$jwk")"
kid="$(jose jwk thp -i- -a "${CLEVIS_DEFAULT_THP_ALG}"  <<< "$jwk")"
jwe='{"protected":{"alg":"ECDH-ES","enc":"A256GCM","clevis":{"pin":"tang","tang":{}}}}'
jwe="$(jose fmt -j "$jwe" -g protected -q "$kid" -s kid -UUo-)"
jwe="$(jose fmt -j "$jwe" -g protected -g clevis -g tang -q "$url" -s url -UUUUo-)"
jwe="$(jose fmt -j "$jwe" -g protected -g clevis -g tang -j- -s adv -UUUUo- <<< "$jwks")"
exec jose jwe enc -i- -k- -I- -c < <(echo -n "$jwe$jwk"; /bin/cat)
