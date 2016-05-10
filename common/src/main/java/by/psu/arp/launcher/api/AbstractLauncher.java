package by.psu.arp.launcher.api;

import by.psu.arp.executor.IExecutor;

import java.util.List;

/**
 * .
 * <p>
 * Created: 30.04.16
 * </p>
 */
public abstract class AbstractLauncher implements ILauncher {

    protected ThreadGroup threadGroup;
    protected List<IExecutor> executors;

    @Override
    public void stop() {
        executors.forEach(IExecutor::stop);
    }
}
