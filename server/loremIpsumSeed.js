/* jshint esversion: 6 */
const csvParser = require('papaparse');

const mongoose = require('mongoose');
const db = require('./models');
// mongoose.set('debug', true);
mongoose.Promise = Promise;

//////////////////////////////////////////

let useCaseList = [
  {
    useCase: `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla sodales sed odio nec mattis.`,
    domain: `Lorem`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Lorem'}, { logSrc: 'Ipsum'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Cras facilisis mattis dolor, vitae semper massa accumsan ullamcorper.`,
    domain: `Ipsum`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Dolor'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae;`,
    domain: `Lorem`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Dolor'}, { logSrc: 'Sit'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Fusce neque augue, aliquam at nisi ut, iaculis sollicitudin lorem. Vivamus ut placerat mi.`,
    domain: `Ipsum`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Vivamus tincidunt aliquet varius.`,
    domain: `Dolor`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Lorem'}, { logSrc: 'Elit'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Ut at sodales dui, laoreet pulvinar urna.`,
    domain: `Sit`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Ut nulla massa, rutrum in maximus ac, pellentesque ut diam.`,
    domain: `Amet`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Ipsum'}, { logSrc: 'Consectectur'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `In arcu massa, vehicula a lobortis et, pulvinar vel augue.`,
    domain: `Amet`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Sit'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Aliquam erat volutpat.`,
    domain: `Consectetur`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Lorem'}, { logSrc: 'Ipsum'}, { logSrc: 'Dolor'}, { logSrc: 'Sit'}, { logSrc: 'Amet'}, { logSrc: 'Consectetur'} 
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Donec porttitor lorem ac cursus fermentum.`,
    domain: `Ipsum`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Adipiscing'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Cras ipsum elit, rhoncus sit amet ullamcorper efficitur, vestibulum iaculis est.`,
    domain: `Elit`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Adipiscing'}, { logSrc: 'Elit'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Sed dui est, egestas ac massa ut, faucibus porta mi.`,
    domain: `Sit`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Adipiscing'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Morbi nec iaculis erat.`,
    domain: `Sit`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Sit'}, { logSrc: 'Elit'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Aenean varius mattis nisl ac gravida.`,
    domain: `Ipsum`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Sit'}, { logSrc: 'Elit'}, { logSrc: 'Amet' }
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Duis nec diam tellus.`,
    domain: `Sit`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Sit'}, { logSrc: 'Lorem'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Suspendisse sagittis dui risus, tempus dictum risus elementum at.`,
    domain: `Elit`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Ipsum'}, { logSrc: 'Lorem'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Suspendisse lacus tellus, pretium at ornare in, pharetra eu metus.`,
    domain: `Dolor`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Dolor'}, { logSrc: 'Lorem'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Donec ac mauris eget risus elementum mattis.`,
    domain: `Sit`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Sit'}, { logSrc: 'Lorem'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  },
  {
    useCase: `Integer leo nunc, mattis non convallis in, dictum in nunc.`,
    domain: `Consectetur`,
    spl: `index=lorem ipsum |stats count by dolor |rare sit| sort -amet`,
    requiredLogSrcs: [
      { logSrc: 'Consectetur'}, { logSrc: 'Lorem'}
    ],
    comments: `Nulla sodales sed odio nec mattis.`
  }
];

//////////////////////////////////////////

let logSrcsList = [
  { logSrc: 'Lorem' },
  { logSrc: 'Ipsum' },
  { logSrc: 'Dolor' },
  { logSrc: 'Sit' },
  { logSrc: 'Amet' },
  { logSrc: 'Consectetur' },
  { logSrc: 'Adipiscing' },
  { logSrc: 'Elit' }
];

let dropAndSeedLogSrcs = function() {
  return new Promise( (resolve, reject) => {
    db.LogSrc.remove({}).then( () => {
      function asyncCreateDoc(doc) {
        return new Promise(resolveAsync => {
          db.LogSrc.create(doc)
            .then(createdDoc => {
              // console.log('CREATED DOCUMENT: ' + createdDoc);
              resolveAsync();
            });
        });
      }
      let createInteractions = logSrcsList.map(asyncCreateDoc);
      let createResults = Promise.all(createInteractions);
      createResults.then( () => {
        // console.log('DONE WITH CREATING LOGSOURCES');
        resolve();
      }).catch(err => {
        console.log('WAS NOT ABLE TO CREATE ALL USECASES', err);
        reject();
      });
    }).catch(err => {
      console.log('COULD NOT REMOVE ALL LOG SOURCES.' + err + ' \n \n \n \n \n \n \n \n');
      reject();
    });
  });
};

let dropAndSeedUseCases = function() {
  return new Promise( (resolve, reject) => {
    db.UseCase.remove({})
      .then( () => {
        function asyncCreateDoc(doc) {
          return new Promise(resolveAsync => {
            db.UseCase.create(doc)
              .then(createdDoc => {
                // console.log('CREATED DOCUMENT: ' + createdDoc);
                resolveAsync();
              });
          });
        }
        let createInteractions = useCaseList.map(asyncCreateDoc);
        let createResults = Promise.all(createInteractions);
        createResults.then( () => {
          // console.log('DONE WITH CREATING USECASES');
          resolve();
        }).catch(err => {
          console.log('WAS NOT ABLE TO CREATE ALL USECASES', err);
          reject();
        });
      }).catch(err => {
        console.log('WAS NOT ABLE TO REMOVE ALL USECASES: ', err);
        reject();
      });
    });
};

/////////////////////////////////////////////////

let dashboardsList = [
  // Rett 47-57
  {
    dashboardName: `Lorem ipsum dolor sit amet, consectetur adipiscing elit.`,
    domain: `Lorem`,
    dashboardXML: `<lorem ipsum>
  <label>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</label>
  <lorem submitButton="affirmative">
    <ipsum type="text" token="dolor sit">
      <dolor>amet, consectetur</dolor>
      <sit>
        <amet>adipiscing</amet>
        <consectetur>elit</consectetur>
      </sit>
    </ipsum>
  </lorem>
  <elit>
    <lorem>
      <ipsum>
        <title>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</title>
        <search>
          <query>proprietaritas</query>
        </search>
        <option name="lorem ipsum">Dolor</option>
        <option name="lorem ipsum dolor sit">Amet</option>
      </ipsum>
    </lorem>
  </elit>
</lorem ipsum>`,
    comments: `Dolor sit`
  },
  {
    dashboardName: `Nulla sodales sed odio nec mattis.`,
    domain: `Ipsum`,
    dashboardXML: `<lorem ipsum>
  <label>Nulla sodales sed odio nec mattis.</label>
  <lorem submitButton="affirmative">
    <ipsum type="text" token="dolor sit">
      <dolor>amet, consectetur</dolor>
      <sit>
        <amet>adipiscing</amet>
        <consectetur>elit</consectetur>
      </sit>
    </ipsum>
  </lorem>
  <elit>
    <lorem>
      <ipsum>
        <title>Nulla sodales sed odio nec mattis.</title>
        <search>
          <query>proprietaritas</query>
        </search>
        <option name="lorem ipsum">Dolor</option>
        <option name="lorem ipsum dolor sit">Amet</option>
      </ipsum>
    </lorem>
  </elit>
</lorem ipsum>`,
    comments: `Dolor sit`
  },
  {
    dashboardName: `Cras facilisis mattis dolor, vitae semper massa accumsan ullamcorper.`,
    domain: `Dolor`,
    dashboardXML: `<lorem ipsum>
  <label>Cras facilisis mattis dolor, vitae semper massa accumsan ullamcorper.</label>
  <lorem submitButton="affirmative">
    <ipsum type="text" token="dolor sit">
      <dolor>amet, consectetur</dolor>
      <sit>
        <amet>adipiscing</amet>
        <consectetur>elit</consectetur>
      </sit>
    </ipsum>
  </lorem>
  <elit>
    <lorem>
      <ipsum>
        <title>Cras facilisis mattis dolor, vitae semper massa accumsan ullamcorper.</title>
        <search>
          <query>proprietaritas</query>
        </search>
        <option name="lorem ipsum">Dolor</option>
        <option name="lorem ipsum dolor sit">Amet</option>
      </ipsum>
    </lorem>
  </elit>
</lorem ipsum>`,
    comments: `Dolor sit`
  },
  {
    dashboardName: `Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae;`,
    domain: `Sit`,
    dashboardXML: `<lorem ipsum>
  <label>Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae;</label>
  <lorem submitButton="affirmative">
    <ipsum type="text" token="dolor sit">
      <dolor>amet, consectetur</dolor>
      <sit>
        <amet>adipiscing</amet>
        <consectetur>elit</consectetur>
      </sit>
    </ipsum>
  </lorem>
  <elit>
    <lorem>
      <ipsum>
        <title>Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae;</title>
        <search>
          <query>proprietaritas</query>
        </search>
        <option name="lorem ipsum">Dolor</option>
        <option name="lorem ipsum dolor sit">Amet</option>
      </ipsum>
    </lorem>
  </elit>
</lorem ipsum>`,
    comments: `Dolor sit`
  },
  {
    dashboardName: `Fusce neque augue, aliquam at nisi ut, iaculis sollicitudin lorem.`,
    domain: `Consectetur`,
    dashboardXML: `<lorem ipsum>
  <label>Fusce neque augue, aliquam at nisi ut, iaculis sollicitudin lorem.</label>
  <lorem submitButton="affirmative">
    <ipsum type="text" token="dolor sit">
      <dolor>amet, consectetur</dolor>
      <sit>
        <amet>adipiscing</amet>
        <consectetur>elit</consectetur>
      </sit>
    </ipsum>
  </lorem>
  <elit>
    <lorem>
      <ipsum>
        <title>Fusce neque augue, aliquam at nisi ut, iaculis sollicitudin lorem.</title>
        <search>
          <query>proprietaritas</query>
        </search>
        <option name="lorem ipsum">Dolor</option>
        <option name="lorem ipsum dolor sit">Amet</option>
      </ipsum>
    </lorem>
  </elit>
</lorem ipsum>`,
    comments: `Dolor sit`
  },
  {
    dashboardName: `Vivamus ut placerat mi.`,
    domain: `Dolor`,
    dashboardXML: `<lorem ipsum>
  <label>Vivamus ut placerat mi.</label>
  <lorem submitButton="affirmative">
    <ipsum type="text" token="dolor sit">
      <dolor>amet, consectetur</dolor>
      <sit>
        <amet>adipiscing</amet>
        <consectetur>elit</consectetur>
      </sit>
    </ipsum>
  </lorem>
  <elit>
    <lorem>
      <ipsum>
        <title>Vivamus ut placerat mi.</title>
        <search>
          <query>proprietaritas</query>
        </search>
        <option name="lorem ipsum">Dolor</option>
        <option name="lorem ipsum dolor sit">Amet</option>
      </ipsum>
    </lorem>
  </elit>
</lorem ipsum>`,
    comments: `Dolor sit`
  }
];

let dropAndSeedDashboards = function dropAndSeedDashboards() {
  return new Promise( (resolve, reject) => {
    db.Dashboard.remove({})
      .then( () => {
        function asyncCreateDoc(doc) {
          return new Promise(resolveAsync => {
            db.Dashboard.create(doc)
              .then(createdDoc => {
                resolveAsync();
              });
          });
        }
        let createInteractions = dashboardsList.map(asyncCreateDoc);
        let createResults = Promise.all(createInteractions);
        createResults.then( () => {
          resolve();
        }).catch(err => {
          console.log('WAS NOT ABLE TO CREATE ALL DASHBOARDS', err);
          reject();
        });
      }).catch(err => {
        console.log('WAS NOT ABLE TO CREATE ALL DASHBOARDS', err);
        reject();
      });
    });
  };

// SEED

dropAndSeedLogSrcs()
  .then( () => {
    console.log('LOG SOURCES SEEDED!');
    dropAndSeedUseCases().then( () => {
      console.log('USECASES SEEDED!');
      dropAndSeedDashboards().then( () => {
        console.log('DATABASE SEEDED!');
        process.exit();
      });
    });
  });
