# Launch a one-off git server from any local repository.

I [tweeted this already][1] but I thought it could use some expansion:

> Enable decentralized git workflow: git config alias.serve "daemon --verbose --export-all --base-path=.git --reuseaddr --strict-paths .git/"

Say you use a git workflow that involves working with a core "official" repository that you pull and push your changes from and into. I'm sure many companies do this, as do many users of git hosting services like Github.

Say that server, or Github, goes down for a bit.

No worries, after all, one of the reasons you use git is so you have a copy of the entire project history in your local clone.

You can keep right on coding and committing, while you wait for the operations team to bring the server back to life. Note to self: buy doughnuts for operations team.

But what if, during this downtime, you want to collaborate with another person, who may not be a git expert, on the same repository?

Or, instead of downtime, what if you and your collaborator are in the field, and for some reason you can't get your VPN to let you connect to your official repo?

Or, what if you and your collaborator are spiking out a bunch of experimental changes, and even though you have access, you don't want to push your unfinished mess into the official central repository? (Not even as feature branches.) Maybe you're in the middle of cleaning up a disastrous rebase or merge and the branches are all over the place.

Well, git, as you are probably aware, is a ["distributed" version control system][2].

Even though you might use a central "official" git repository in your workflow, you still have the ability to use git in a peer-to-peer manner, where you and your collaborator simply build and share commits with each other, and the central server never even has to know.

So, how do you get your branches and commits over to them, or vice versa?

- You could use git's facilities for e-mailing patches. But that's a bit inelegant and requires some knowledge on their end of how to apply e-mailed patches.
- You could create an account on your own machine for your collaborator to ssh into. But maybe you don't have local root access, or maybe you don't trust them with SSH access to your box.
- You could clone your repo onto a thumbdrive and pass it back and forth. But that's rather tedious, especially if you happen to be on the same local network, and requires a thumb drive.

You can probably think of other methods, too. But there's a super easy way: if you can see each other on the network, you can launch a one-off git server that they can use as their remote to clone, fetch, and pull your changes, and kill it when you're done with it.

The tool that enables this is `git daemon`, which has a lot of options and functionality, but for the purpose of enabling this easy one-off "just serve up the repo I'm in," the way to use it is to create an alias. I like to call it `git serve`. Run:

    git config --global alias.serve "daemon --verbose --export-all --base-path=.git --reuseaddr --strict-paths .git/"

Using an alias is actually crucial, because git aliases are executed in the base directory of your working tree. So the path '.git' will always point to the right place, no matter where you are within the directory tree of your repository.

Use your new `git serve` like so:

1. Run `git serve`. "Ready to rumble," it will report. Git is bad-ass.
2. Find out your IP address. Say it's 192.168.1.123.
3. Say "hey Jane, I'm not ready/able to push these commits up to origin, but you can fetch my commits into your clone by running `git fetch git://192.168.1.123/`"
4. Press ctrl+c when you don't want to serve that repo any longer.

You could also tell Jane to `git clone git://192.168.1.123/ local-repo-name` if she does not yet have a clone of the repository. Or, use `git pull git://192.168.1.123/ branchname` to do a fetch and merge at once, useful if you are working together on a feature branch.

Note however that you shouldn't do this on hostile networks if you keep secrets in your repository, because there's no authentication. It doesn't advertise its existence, but anybody with a a port scanner can find it, connect to it, and clone your repo.

But it's not super dangerous because it is read-only by default. Read the `git daemon` man page carefully if you think that you want to enable write access. In the case where you want to obtain your collaborator's commits, it's much safer to leave it read-only, and ask your collaborator to also run this command, so you can pull from them.

Tangentially related: on the subject of one-off servers, if you want to temporarily share a bunch of static files over HTTP: `python -m SimpleHTTPServer`

[1]: https://twitter.com/datagrok/status/307947786853285888
[2]: http://git-scm.com/about/distributed
