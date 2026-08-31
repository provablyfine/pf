Check that pf license does not show frpc license

  $ pf license | grep -i frpc
  [1]

Check that pfa license does not show frpc license

  $ pfa license | grep -i frpc
  [1]

Check that provablyfine license is shown in pf license

  $ pf license | grep -i "provablyfine" | wc -l
  1

Check that provablyfine license is shown in pfa license

  $ pfa license | grep -i "provablyfine" | wc -l
  1
