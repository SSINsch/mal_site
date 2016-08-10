# mal_site

————————————————————————————————————

mal_site (using WINDIVERT)
============
check if the user entered malicious sites.
if so, drop the packet


+ open windivert
+ check if HTTP packet
+ get URL
+ check if malicious site
+ if so, drop the packet
+ ????
+ ##PROFIT!

// improvement?
+ if the user entered malicious sites simultaneously, the log recognize the first site only.
+ we can make the site redirect to the site like 'warning.or.kr'
+ for the better performance, we can use hash, binary search(sorting required)... etc

——————————————————————————————————————-
