CLEVIS_DEFAULT_THP_ALG=S256       # SHA-256.
CLEVIS_DEFAULT_THP_LEN=43         # Length of SHA-256 thumbprint.
CLEVIS_ALTERNATIVE_THP_ALGS=S1    # SHA-1.

read -r -d . hdr

jhd="$(jose b64 dec -i- <<< "$hdr")"
clt="$(jose fmt -j- -Og epk -Oo- <<< "$jhd")"
kid="$(jose fmt -j- -Og kid -Su- <<< "$jhd")"
keys="$(jose fmt -j- -Og clevis -g tang -g adv -Oo- <<< "${jhd}")"
srv="$(jose jwk thp -i- -f "${kid}" -a "${CLEVIS_DEFAULT_THP_ALG}" <<< "${keys}")"
url="$(jose fmt -j- -Og clevis -g tang -g url -Su- <<< "$jhd")"
crv="$(jose fmt -j- -Og crv -Su- <<< "$clt")"
eph="$(jose jwk gen -i "{\"alg\":\"ECMR\",\"crv\":\"$crv\"}")"
xfr="$(jose jwk exc -i '{"alg":"ECMR"}' -l- -r- <<< "$clt$eph")"

rec_url="$url/rec/$kid"
ct="Content-Type: application/jwk+json"

rep="$(curl -sfg -X POST -H "$ct" --data-binary @- "$rec_url" <<< "$xfr")"
rep="$(jose fmt -j- -Og kty -q EC -EUUg crv -q "$crv" -EUUo- <<< "$rep")"
tmp="$(jose jwk exc -i '{"alg":"ECMR"}' -l- -r- <<< "$eph$srv")"
rep="$(jose jwk pub -i- <<< "$rep")"
jwk="$(jose jwk exc -l- -r- <<< "$rep$tmp")"
echo "local: $rep"
echo "remote: $tmp"
echo "done: $jwk"
echo "clt: $clt"
(echo -n "$jwk$hdr."; /bin/cat) | jose jwe dec -k- -i-
