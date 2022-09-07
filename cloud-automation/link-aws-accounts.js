const puppeteer = require("puppeteer");
const fs = require("fs");
const readline = require("readline");
const path = require("path");

const headless = true;
const username = process.env.USERNAME;
const password = process.env.PASSWORD;

class Job {
  constructor(id, cb) {
    this.id = id;
    this.cb = cb;
    this.status = "new";
  }
  setStatus(status) {
    this.status = status;
  }
  getStatus() {
    return this.status;
  }
  getCallback() {
    return this.cb;
  }
}
class JobQueueInstance {
  constructor() {
    this.queue = [];
  }
  enqueue(job) {
    this.queue.push(job);
  }
  hasRunningJob() {
    return this.queue.some((job) => job.getStatus() === "running");
  }
  dequeque() {
    if (!this.isEmpty()) {
      return this.queue.shift();
    }
  }
  isEmpty() {
    return this.queue.length == 0;
  }
  front() {
    if (this.queue.length > 0) {
      return this.queue[0];
    }
  }
  print() {
    return this.queue.map((job) => job.id);
  }
  async process() {
    if (!this.isEmpty() && !this.hasRunningJob()) {
      const job = this.front();
      job.setStatus("running");
      const cb = job.getCallback();
      await cb();
      this.dequeque();
      console.log(`Process completed with jobId: ${job.id}`);
    }
  }
}
class JobQueue {
  constructor() {
    throw new Error("Use JobQueue.getInstance()");
  }
  static getInstance() {
    if (!JobQueue.instance) {
      JobQueue.instance = new JobQueueInstance();
    }
    return JobQueue.instance;
  }
}

async function gotoPrivatePage({ page }, url) {
  await page.goto(url, { waitUntil: "networkidle0" });

  await page.type("#username-verification", username);
  await page.click("#login-show-step2");
  await page.waitForSelector("#password", { visible: true });
  await page.type("#password", password);

  await Promise.all([
    page.click("#rh-password-verification-submit-button"),
    page.waitForNavigation({ waitUntil: "networkidle0" }),
  ]);
}

async function skipGdpr({ page }) {
  const cookies = [
    { name: "notice_behavior", value: "expressed,eu", domain: ".redhat.com" },
    { name: "notice_gdpr_prefs", value: "0,1,2:", domain: ".redhat.com" },
  ];
  await page.setCookie(...cookies);
}

async function addAwsAccount({ browser }, { accountId, sandboxName }) {
  const page = await browser.newPage();
  console.log(`Adding AWS account for ${accountId}`);
  await page.goto("https://access.redhat.com/management/cloud/AWS/accounts/new", { waitUntil: "networkidle0" });
  await page.type("#forms_cloud_accounts_create_accounts_0_id", accountId);
  await page.type("#forms_cloud_accounts_create_accounts_0_nickname", sandboxName);
  await page.click("input[type=submit]");
  try {
    await page.waitForNavigation({ waitUntil: "networkidle0" });
  } catch {}
  if (page.url() !== "https://access.redhat.com/management/cloud") {
    console.error(`Error adding account ${accountId}`);
  } else {
    console.log(`AWS account for ${accountId} added succesfully`);
  }
  await page.close();
}

async function linkAwsAccounts({ browser, page }) {
  await gotoPrivatePage({ page }, "https://access.redhat.com/management/cloud");
  await page.waitForFunction('[...document.querySelectorAll("a")].some(x => x.innerText.includes("AWS Accounts"))', {
    timeout: 120000,
  });
  const promises = [];
  await new Promise((resolve) => {
    const readInterface = readline.createInterface({
      input: fs.createReadStream(path.join(__dirname, "new_sandboxes.txt")),
    });
    const jobQueue = JobQueue.getInstance();
    let lineno = -1;

    readInterface
      .on("line", function (line) {
        lineno++;
        if (lineno === 0) return;
        const [sandboxName, accountId] = line.split(" ");
        const account = { accountId, sandboxName };
        promises.push(
          new Promise((resolve) => {
            setTimeout(() => {
              page
                .waitForFunction(
                  `[...document.querySelectorAll("td")].some(x => x.innerText.includes("${account.accountId}"))`
                )
                .then(() => {
                  console.log(`AWS Account ${account.accountId} already exists`);
                  resolve();
                })
                .catch(() => {
                  const job = new Job(account.accountId, async () => await addAwsAccount({ browser }, account));
                  jobQueue.enqueue(job);
                  resolve(`Job ${account.accountId} enqueued`);
                });
            }, 500 * lineno);
          })
        );
      })
      .on("close", () => {
        resolve("Finished");
      });
  });
  await Promise.all(promises);
}

(async () => {
  const jobQueue = JobQueue.getInstance();
  setInterval(() => jobQueue.process(), 5000);
  const browser = await puppeteer.launch({
    headless,
  });
  const page = await browser.newPage();
  await skipGdpr({ page });
  await linkAwsAccounts({ browser, page });
  jobQueue.enqueue(
    new Job("close browser", async () => {
      console.log("AWS account assignation complete");
      await browser.close();
      process.exit();
    })
  );
})();
