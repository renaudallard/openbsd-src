\ Forth tokenizer test
fcode-version2
headers
" hello" name

: test-word ( -- )
   ." Hello, World!" cr
;

new-device
  " test" device-name
  " test,device" device-type
finish-device

fcode-end
