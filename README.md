## ghidra-frida: 
- Description: support for Frida-based analysis using the Ghidra traceRMI
- Author: d-millar

## Build Guide

### Step-by-Step Compilation Instructions

#### Clone the Repository
```bash
~\repos\ghidra$ git clone https://github.com/nblog/ghidra-frida Ghidra\Debug\Debugger-agent-xfrida
```

#### Initialize and Fetch Dependencies
```bash
.\gradlew -I gradle/support/fetchDependencies.gradle
```
This command initializes the Gradle environment and downloads all required dependencies specified in the build configuration.

#### Build the Python Package
```bash
.\gradlew :Debugger-agent-xfrida:buildPyPackage
```
This builds the Python package that integrates Frida with Ghidra's trace RMI interface.