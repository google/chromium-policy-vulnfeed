# Chromium Policy Vulnfeed

Chromium Policy Vulnfeed is a project that aims to add the capability to vulnerability scanners
to find repositories that are using outdated, and therefore security vulnerable versions of packages such as
V8.

Which versions of these packages are considered outdated is based on a policy that the package owners can define.
The policy is parsed by this code and a vulnerability feed is created that vulnerability databases such as
OSV.dev can pick up.

The code is generic enough to support a variety of software, but it's currently focused on Chromium related software.

Apache header:

    Copyright 2024 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
