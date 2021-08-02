using System;
using System.IO;
using CommandLine;

namespace EasyHash.ConsoleApp
{
    class Program
    {
        public class Options
        {
            [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages.")]
            public bool Verbose { get; set; }

            [Option('p', "path", Required = true)]
            public string Path { get; set; }
        }

        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(o =>
                {
                    var cracker = new Cracker(o.Path, (s) =>
                    {
                        if (o.Verbose)
                        {
                            Console.WriteLine(s);
                        }
                    });

                    try
                    {
                        var result = cracker.FindPassword();
                        Console.WriteLine(result);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                });
        }
    }
}