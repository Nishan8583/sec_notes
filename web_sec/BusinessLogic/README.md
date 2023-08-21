1. Integer overflow, keep adding items soo much, value goes to negative, buy multiple items to get within range.
2. `Inconsistent handling of exceptional input` String truncation. This is a wierd lab. Lets say `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dontwannacry.com.exploit-0a0600ce03a6e00c82f6bcf5018e007d.exploit-server.net`. and I register. the email gets truncated till `AAA....@dontwannacry.com` (i.e.) 255 chars. Admin panel only accessible to @donwannacry users. And since the domain is in `exploit-0a0600ce03a6e00c82f6bcf5018e007d.exploit-server.net`, we get the registration email.
3. `Weak isolation on dual-use endpoint` When password change, change username and remove current password field. Using the following notes from portswigger:
```
Only remove one parameter at a time to ensure all relevant code paths are reached.
Try deleting the name of the parameter as well as the value. The server will typically handle both cases differently.
Follow multi-stage processes through to completion. Sometimes tampering with a parameter in one step will have an effect on another step further along in the workflow.
```
4. Test especially when multiple step is present.
