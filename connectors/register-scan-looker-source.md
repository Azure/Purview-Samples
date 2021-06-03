# Register and Scan Looker(Preview)

This article outlines how to register a Looker Server in Purview and set
up a scan.

## Supported capabilities

The Looker source supports Full scan to extract metadata from a Looker
server. It imported metadata from a Looker server, including database
connections, LookML Models and associated reports (Looks and
Dashboards). This data source also fetches Lineage between data assets.

## Prerequisites

1.  Set up the latest [self-hosted integration
    runtime](https://www.microsoft.com/download/details.aspx?id=39717).
    For more information, see [Create and configure a self-hosted
    integration
    runtime](https://docs.microsoft.com/azure/data-factory/create-self-hosted-integration-runtime).

2.  Make sure [JDK
    11](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html)
    is installed on your virtual machine where self-hosted integration
    runtime is installed.

3.  Make sure \"Visual C++ Redistributable 2012 Update 4\" is installed
    on the VM where self-hosted integration runtime is running. If you
    don\'t have it installed, download it from
    [here](https://www.microsoft.com/download/details.aspx?id=30679).

4.  Supported Looker server version is 7.2

## Feature Flag

Registration and scanning of BigQuery source is available behind a
feature flag. Append the following to your URL:
&feature.ext.datasource={\"looker\":\"true\"}

> E.g., full URL
> [https://web.purview.azure.com/?feature.ext.datasource={\"looker\":\"true\"}](https://web.purview.azure.com/?feature.ext.datasource=%7b%22looker%22:%22true%22%7d)

## Setting up authentication for a scan

An API3 key is required to connect to the Looker server. The API3 key
consists in a public client_id and a private client_secret and follows
an OAuth2 authentication pattern.

## Register a Looker server

To register a new Looker server in your data catalog, do the following:

1. Navigate to your Purview account.
2. Select **Sources** on the left navigation.
3. Select **Register.**
4. On Register sources, select **Looker**. Select **Continue.**

    <img src="media\register-scan-looker-source\image1.png"
     alt="image1"
     style="float: left; margin-right: 10px;" />

On the Register sources (Looker) screen, do the following:

1. Enter a **Name** that the data source will be listed within the
    Catalog.

2. Enter the Looker API URL in the **Server API URL** field. The
    default port for API requests is port 19999. Also, all Looker API
    endpoints require an HTTPS connection. For example,
    https://azurepurview.cloud.looker.com

3. Select a collection or create a new one (Optional)

4. Finish to register the data source.

<img src="media\register-scan-looker-source\image2.png"
     alt="image2"
     style="float: left; margin-right: 10px;" />

## Creating and running a scan

To create and run a new scan, do the following:

1. In the Management Center, click on Integration runtimes. If it is
    not set up, use the steps mentioned
    [here](https://docs.microsoft.com/azure/purview/manage-integration-runtimes)
    to setup a self-hosted integration runtime

2. Navigate to **Sources**.

3. Select the registered **Looker** server.

4. Select **+ New scan**.

5. Provide the below details:

    a.  **Name**: The name of the scan

    b.  **Connect via integration runtime**: Select the configured
        self-hosted integration runtime.

    c.  **Server API URL** is auto populated based on the value entered
        during registration.

    d.  **Credential:** While configuring Looker credential, make sure
        to:

    - Select **Basic Authentication** as the Authentication method
    - Provide your Looker API3 key's client ID in the User name field
    - Save your Looker API3 key's client secret in the key vault's secret.

    **Note:** To access client ID and client secret, navigate to Looker -\>Admin -\> Users -\> Click on **Edit** on an user -\> Click on **EditKeys** -\> Use the Client ID and Client Secret or create a new one.
    
    <img src="media\register-scan-looker-source\image3.png"
     alt="image3"
     style="float: left; margin-right: 10px;" />



    To understand more on credentials, refer to the link [here](https://docs.microsoft.com/en-us/azure/purview/manage-credentials)

    e.  **Project filter** -- Scope your scan by providing a semi colon
    separated list of Looker projects. This option is used to select
    looks and dashboards by their parent project.

    f.  **Maximum memory available**: Maximum memory (in GB) available on
    customer's VM to be used by scanning processes. This is dependent on
    the size of erwin Mart to be scanned.


<img src="media\register-scan-looker-source\image4.png" alt="image4" style=" margin-right: 10px;" />

6. Click on **Test connection.**

7. Click on **Continue**.

8. Choose your **scan trigger**. You can set up a schedule or ran the
    scan once.

9. Review your scan and click on **Save and Run**.
