# go-sanitize

A Go port of the Flamework lib_sanitize library.

## Important

YOU SHOULD NOT TRY TO USE THIS YET. IT DOES NOT WORK. IT HAS NOT BEEN TESTED. IT IS NOT SAFE. NO.

## Example

```
package main

import (
       "fmt"
       "sanitize"
       )

func main() {

     input := "foo bar\nbaz"
     
     opts := sanitize.DefaultOptions()
     output, _ := sanitize.SanitizeString(input, opts)

     fmt.Println(output)
}
```     

## See also

* https://github.com/exflickr/flamework/blob/master/www/include/lib_sanitize.php
