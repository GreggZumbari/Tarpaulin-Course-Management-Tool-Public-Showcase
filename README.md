# Tarpaulin Course Management Tool
Greggory Hickman, June 2025<br />
Last updated March 2026

This was my portfolio assignment for my CS 493 course at Oregon State University in June 2025. This particular implementation of the assignment has additional functionality beyond the scope of the original project requirements, including a frontend UI which can be accessed with a web browser. To see the original project requirements, please see the project requirements document at `docs\assignment6-api-doc.pdf`.

This app was tested on Windows 10, Windows 11, macOS 15, and macOS 26.

## Setup steps

In order for this web app to function, you'll need accounts with both [auth0](https://auth0.com/) and [Google Cloud](https://cloud.google.com/), the latter of which will require you to attach a credit card, debit card, or bank account in order to create an account. This is because Google Cloud (GCP) lets you use Google's servers to actually run your web app, which costs money. If you set it up correctly, which this README file will show you how to do, it shouldn't cost more than a few cents per month. We will also be using GCP's [Datastore](https://console.cloud.google.com/datastore) as our database, where we will store all data involved with the web app.

The following tutorial was last updated in March 2026, and is non-exhaustive. For a more in-depth tutorial on the tools used in this project, please see the following links.

auth0: [https://auth0.com/docs/get-started](https://auth0.com/docs/get-started)

Create a Google Cloud project: [https://developers.google.com/workspace/guides/create-project](https://developers.google.com/workspace/guides/create-project)

GCP Datastore: [https://docs.cloud.google.com/datastore/docs/store-query-data?hl=en](https://docs.cloud.google.com/datastore/docs/store-query-data?hl=en)

GCP Cloud Storage buckets: [https://docs.cloud.google.com/storage/docs/buckets](https://docs.cloud.google.com/storage/docs/buckets)

1. In a terminal/command prompt, navigate to the folder that this project is contained with, and type the following command to install all the required python packages:

`pip install -r requirements.txt`

2. Make an account with [Google Cloud](https://cloud.google.com/), and create a project. 

3. Navigate to `Datastore` or `Firestore` and create a database. You should keep the Database ID field as `(default)`. Keep all default settings, but select `Firestore with Datastore compatibility` under `Modes`, and select `Region` under `Location Type`. From the drop down list labelled `Region`, choose the region closest to you.

4. Navigate to `Cloud Storage`, go to `Buckets`, and create a bucket. You can name this whatever you like, but it has to be something unique that no one else has chosen before. Keep all default settings, but just like before, select `Region` under `Location Type` and choose the region closest to you.

5. Make an account with [auth0](https://auth0.com/), and create an application.

6. Navigate to the `Settings` tab, and under `General`, scroll down until you see the `API Authorization Settings` section. In the `Default Directory` field, enter `Username-Password-Authentication`.

7. Navigate to the `Applications` tab, select `Applications`, select your application, select the `APIs` tab, and click the `Edit` button next to the `Auth0 Management API`. Authorize `create:users`, `create:roles`, and `create:role_members`. This will allow us to create users using a script rather than having to do it all manually.

8. On the same page, select `Settings`. Now, go back to this project's files, and navigate to the `/docs` directory. Copy the `Domain`, `Client ID`, and `Client Secret` into the `DOMAIN`, `CLIENT_ID`, and `CLIENT_SECRET` variables in the `/docs/credentials.json` file found in this folder. Do not share the `Client Secret` value with anybody. Also copy the name of your Google Cloud Bucket that you made in step 4 in the `PHOTO_BUCKET` variable.

9. Run the `project_setup.py` script with this command:

`python project_setup.py`

You can see the users and roles that will be created with the `project_setup.py` in `users_roles.json`

If this script doesn't work, delete all existing roles and users from the Auth0 webpage and try again.

10. That's it for the setup! Proceed to the `Steps to run the Web App on a Development Server` section.

## Steps to run the Web App on a Development Server

Your Datastore client contains all of the data that this web app will store and retrieve as part of it's functionality. To connect to your Datastore client, run the following command and follow the login steps that will pop up afterwards:

`gcloud auth application-default login`

Then, you can run the web app with this command:

`python main.py`

The console will then tell you what port the app is running on, port `8080` by default. You can visit the physical web page in your web browser by typing `http://127.0.0.1:8080` into your URL/search bar.