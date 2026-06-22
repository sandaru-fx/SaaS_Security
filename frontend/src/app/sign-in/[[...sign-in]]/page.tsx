import { SignIn } from "@clerk/nextjs";

export default function SignInPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <SignIn
        routing="path"
        path="/sign-in"
        signUpUrl="/sign-up"
        appearance={{
          elements: {
            rootBox: "mx-auto",
            card: "bg-zinc-900 border border-zinc-800 shadow-xl",
            headerTitle: "text-zinc-50",
            headerSubtitle: "text-zinc-400",
            socialButtonsBlockButton: "border-zinc-700 text-zinc-200",
            formFieldLabel: "text-zinc-300",
            formFieldInput: "bg-zinc-800 border-zinc-700 text-zinc-50",
            footerActionLink: "text-emerald-400 hover:text-emerald-300",
            formButtonPrimary: "bg-emerald-500 hover:bg-emerald-400 text-zinc-950",
          },
        }}
      />
    </div>
  );
}
