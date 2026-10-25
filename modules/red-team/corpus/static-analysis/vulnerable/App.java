import org.apache.logging.log4j.LogManager;

class App {
    void run(String command) throws Exception {
        LogManager.getLogger(App.class).info("running command");
        Runtime.getRuntime().exec(command);
    }
}
